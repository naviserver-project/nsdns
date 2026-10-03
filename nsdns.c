/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * The Initial Developer of the Original Code and related documentation
 * is America Online, Inc. Portions created by AOL are Copyright (C) 1999
 * America Online, Inc. All Rights Reserved.
 *
 */

/*
 *   NaviServer DNS support - library functions
 *
 *   Author Vlad Seryakov vlad@crystalballinc.com
 *   Gustaf Neumann neumann@wu.ac.at
 *
 */

#include "ns.h"
#include "dns.h"

typedef struct _dnsClient {
    Ns_RWLock lock;
    char ipaddr[NS_IPADDR_SIZE];
    Tcl_HashTable list;
    struct _dnsClient *link;
    unsigned long rcount;
    unsigned short rstats[256];
} dnsClient;

/* DNS request */
typedef struct _dnsRequest {
    struct _dnsRequest *next, *prev;
    int sock;
    unsigned int flags;
    dnsPacket *req;
    dnsPacket *reply;
    dnsClient *client;
    struct NS_SOCKADDR_STORAGE sa;
    unsigned short proxy_id;
    unsigned short proxy_count;
    unsigned long proxy_time;
    struct timeval recv_time;
    struct timeval start_time;
    char buffer[DNS_BUF_SIZE + 1];
    ssize_t size;
} dnsRequest;

typedef struct _dnsQueue {
    int id;
    Ns_Cond cond;
    Ns_Mutex lock;
    unsigned long size;
    unsigned long maxsize;
    unsigned long requests;
    unsigned long rtime;
    unsigned long wtime;
    struct _dnsRequest *head;
    struct _dnsRequest *tail;
    struct _dnsRequest *freelist;
} dnsQueue;

static void *dnsRequestCreate(int sock, char *buf, size_t len);
static void dnsRequestFree(dnsRequest *req);
static ssize_t dnsRequestSend(dnsRequest *req);
static int dnsRequestHandle(dnsRequest *req);
static int dnsRequestFind(dnsRequest *req, dnsRecord *qlist, unsigned int depth);
static void dnsRecordCache(dnsClient *client, dnsRecord **list);
static ssize_t dnsWrite(int sock, void *vbuf, size_t len);
static ssize_t dnsRead(int sock, void *vbuf, size_t len);
static TCL_OBJCMDPROC_T DnsCmd;

static Ns_TclTraceProc DnsInterpInit;
static Ns_SockProc DnsTcpListen;

static void DnsTcpThread(void *arg);
static void DnsProxyThread(void *arg);
static void DnsQueueListenThread(void *arg);
static void DnsQueueRequestThread(void *arg);
static dnsClient *DnsClientFind(char *host, struct sockaddr *saPtr);
static dnsClient *DnsClientCreate(char *host);
static void DnsClientLink(char *host, char *host2);
static int DnsClientResolve(const char *host, struct sockaddr *saPtr);

static unsigned short dnsID = 0u;
static int dnsPort;
static int dnsReadTimeout;
static int dnsWriteTimeout;
static int dnsProxyTimeout;
static int dnsNegativeTTL;
static unsigned long dnsCacheTTL;
static int dnsUdpSock;
static int dnsTcpSock;
static int dnsProxyPort;
static int dnsProxySock = -1;
static int dnsThreads;
static int dnsRcvBuf;
static int dnsProxyRetries;
static const char *dnsProxyHost = NULL;
static const char *dnsDefaultHost = NULL;
static Ns_Cond dnsProxyCond;
static Ns_Mutex dnsProxyMutex;
static dnsRequest *dnsProxyQueue = NULL;
//static struct sockaddr_in dnsProxyAddr;
static struct NS_SOCKADDR_STORAGE dnsProxyAddr;
static struct sockaddr *dnsProxyAddrPtr = (struct sockaddr *)&dnsProxyAddr;
static dnsQueue dnsQueues[DNS_QUEUE_SIZE];
static Ns_RWLock dnsClientLock;
static Tcl_HashTable dnsClientList;
static dnsClient dnsClientDflt;
static Ns_LogSeverity DnsdDebug;    /* Severity at which to log verbose debugging. */

NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

#if defined(NS_MODULE_INFO_VERSION) && defined(NS_MODULE_TAG)
NS_EXPORT Ns_ModuleInfoProc Ns_ModuleGetInfo;

NS_EXPORT void
Ns_ModuleGetInfo(Ns_ModuleInfo *infoPtr)
{
    Ns_ModuleInfoInit(infoPtr, NS_MODULE_INFO_VERSION, NS_MODULE_NAME,
                      DNS_VERSION, NS_MODULE_TAG, "module", 1u);
}
#endif

NS_EXPORT Ns_ReturnCode Ns_ModuleInit(const char *server, const char *module)
{
    const char *path, *address;
    int         intValue;

    Ns_Log(Notice, "nsdns module version %s server: %s", DNS_VERSION, server);

    DnsdDebug = Ns_CreateLogSeverity("Debug(dnsd)");

    Ns_RWLockInit(&dnsClientLock);
    //Tcl_InitHashTable(&dnsClientList, TCL_ONE_WORD_KEYS);
    Tcl_InitHashTable(&dnsClientList, TCL_STRING_KEYS);
    memset(&dnsClientDflt, 0, sizeof(dnsClient));
    strcpy(dnsClientDflt.ipaddr, "0.0.0.0");
    Ns_RWLockInit(&dnsClientDflt.lock);
    Tcl_InitHashTable(&dnsClientDflt.list, TCL_STRING_KEYS);
    memset(&dnsQueues, 0, sizeof(dnsQueues));

    path = Ns_ConfigGetPath(server, module, (char *)0);
    address = Ns_ConfigGetValue(path, "address");

    if (Ns_ConfigGetInt(path, "flags", &intValue) && intValue > 0) {
        dnsFlags = (unsigned int)intValue;
    } else {
        dnsFlags = 0u;
    }
    if (!Ns_ConfigGetInt(path, "debug", &dnsDebug)) {
        dnsDebug = 0;
    } else {
        (void)Ns_LogSeveritySetEnabled(DnsdDebug, NS_TRUE);
        Ns_Log(DnsdDebug, "debug is enabled");
    }
    if (!Ns_ConfigGetInt(path, "port", &dnsPort)) {
        dnsPort = 5353;
    }
    if (Ns_ConfigGetInt(path, "ttl", &intValue) && intValue > 0) {
        dnsTTL = (unsigned long)intValue;
    } else {
        dnsTTL = 86400u;
    }
    if (!Ns_ConfigGetInt(path, "negativettl", &dnsNegativeTTL)) {
        dnsNegativeTTL = 3600;
    }
    if (Ns_ConfigGetInt(path, "cachettl", &intValue) && intValue > 0) {
        dnsCacheTTL = (unsigned int)intValue;
    } else {
        dnsCacheTTL = 0u;
    }
    if (!Ns_ConfigGetInt(path, "rcvbuf", &dnsRcvBuf)) {
        dnsRcvBuf = 0;
    }
    if (!Ns_ConfigGetInt(path, "readtimeout", &dnsReadTimeout)) {
        dnsReadTimeout = 30;
    }
    if (!Ns_ConfigGetInt(path, "writetimeout", &dnsWriteTimeout)) {
        dnsWriteTimeout = 30;
    }
    if (!Ns_ConfigGetInt(path, "proxytimeout", &dnsProxyTimeout)) {
        dnsProxyTimeout = 3;
    }
    if (!Ns_ConfigGetInt(path, "proxyretries", &dnsProxyRetries)) {
        dnsProxyRetries = 2;
    }
    if (!Ns_ConfigGetInt(path, "threads", &dnsThreads)) {
        dnsThreads = 1;
    }
    if (dnsThreads < 1 || dnsThreads > DNS_QUEUE_SIZE || dnsPort < 0 || dnsPort > 65535) {
        Ns_Log(Error, "nsdns: invalid threads (1..%d) or port (0..65535)", DNS_QUEUE_SIZE);
        return NS_ERROR;
    }
    dnsDefaultHost = Ns_ConfigGetValue(path, "defaulthost");
    if (Ns_ConfigGetValue(path, "nameserverport") == NULL) {
        intValue = 53;
    } else if (!Ns_ConfigGetInt(path, "nameserverport", &intValue)
               || intValue < 1 || intValue > 65535) {
        Ns_Log(Error, "nsdns: nameserverport must be an integer in the range 1..65535");
        return NS_ERROR;
    }
    dnsInit("port", intValue);
    /* Resolving dns servers */
    dnsInit("nameserver", Ns_ConfigGetValue(path, "nameserver"), (char *)NULL);

    /* If no port specified it will be just client dns resolver module */
    if (dnsPort > 0) {
        int n, i;

        /* UDP socket */
        if ((dnsUdpSock = Ns_SockListenUdp(address, (unsigned short)dnsPort, NS_FALSE)) == -1) {
            Ns_Log(Error, "nsdns: udp: [%s]:%d: couldn't create socket: %s",
                   address, dnsPort, strerror(errno));
            return NS_ERROR;
        }
        /* TCP socket */
        if ((dnsTcpSock = Ns_SockListen(address, (unsigned short)dnsPort)) == -1) {
            Ns_Log(Error, "nsdns: tcp: [%s]:%d: couldn't create socket: %s",
                   address, dnsPort, strerror(errno));
            return NS_ERROR;
        }
        /* Use NS callback facility because TCP is not going to be very busy */
        Ns_SockCallback(dnsTcpSock, DnsTcpListen, 0,
                        NS_SOCK_READ | NS_SOCK_EXIT | NS_SOCK_EXCEPTION);
        /* DNS proxy thread */
        if (!Ns_ConfigGetInt(path, "proxyport", &dnsProxyPort)) {
            dnsProxyPort = 53;
        }
        if ((dnsProxyHost = Ns_ConfigGetValue(path, "proxyhost"))) {
            if (Ns_GetSockAddr(dnsProxyAddrPtr, dnsProxyHost, (unsigned short)dnsProxyPort) == NS_OK) {
                dnsProxySock = socket(dnsProxyAddrPtr->sa_family, SOCK_DGRAM, 0);
            }
            if (dnsProxySock == -1) {
                ns_sockclose(dnsUdpSock);
                ns_sockclose(dnsTcpSock);
                Ns_Log(Error, "nsdns: create proxy thread [%s]:%d: %s", dnsProxyHost, dnsProxyPort, strerror(errno));
                return NS_ERROR;
            }
            Ns_Log(DnsdDebug, "nsdns: create proxy thread, host %s port %d", dnsProxyHost, dnsProxyPort);
            Ns_ThreadCreate(DnsProxyThread, 0, 0, 0);
        }
        if (dnsRcvBuf != 0) {
            setsockopt(dnsUdpSock, SOL_SOCKET, SO_RCVBUF, &dnsRcvBuf, sizeof(dnsRcvBuf));
            setsockopt(dnsUdpSock, SOL_SOCKET, SO_SNDBUF, &dnsRcvBuf, sizeof(dnsRcvBuf));
        }
        /* Start queue threads */
        for (n = 0; n < dnsThreads; n++) {
            dnsQueues[n].id = n;
            Ns_MutexInit(&dnsQueues[n].lock);
            /* Preallocate SIP tickets */
            for (i = 0; i <= dnsThreads * 10; i++) {
                dnsRequest *req = ns_calloc(1, sizeof(dnsRequest));
                req->next = dnsQueues[n].freelist;
                dnsQueues[n].freelist = req;
            }
            Ns_ThreadCreate(DnsQueueRequestThread, &dnsQueues[n], 0, 0);
        }
        /* Start listen thread */
        Ns_ThreadCreate(DnsQueueListenThread, 0, 0, 0);
    }
    Ns_MutexSetName2(&dnsProxyMutex, "nsdns", "proxy");
    Ns_Log(Notice, "nsdns: version %s listening on [%s]:%d, (udp %d, tcp %d)",
           DNS_VERSION, (address != 0) ? address : "0.0.0.0", dnsPort,
           dnsUdpSock, dnsTcpSock);
    Ns_TclRegisterTrace(server, DnsInterpInit, 0, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 * Add ns_dns commands to interp.
 */
static int DnsInterpInit(Tcl_Interp *interp, const void *UNUSED(arg))
{
    TCL_CREATEOBJCOMMAND(interp, "ns_dns", DnsCmd, NULL, NULL);
    return TCL_OK;
}

static unsigned long GetUlong(Tcl_Obj *obj)
{
    unsigned long result;
    long          value = strtol(Tcl_GetString(obj), NULL, 10);

    if (value >= 0u) {
        result = (unsigned long)value;
    } else {
        result = 0u;
    }
    return result;
}

static unsigned short GetUshort(Tcl_Obj *obj)
{
    unsigned short result;
    long           value = strtol(Tcl_GetString(obj), NULL, 10);

    if (value >= 0u) {
        result = (unsigned short)value;
    } else {
        result = 0u;
    }
    return result;
}

static short GetShort(Tcl_Obj *obj)
{
    short result;
    long  value = strtol(Tcl_GetString(obj), NULL, 10);

    if (value >= 0) {
        result = (short)value;
    } else {
        result = 0;
    }
    return result;
}

static int DnsCmd(ClientData UNUSED(arg), Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const objv[])
{
    enum commands {
        cmdAdd, cmdDel, cmdFlush, cmdList, cmdResolve, cmdQueue, cmdLookup, cmdStat, cmdFind,
        cmdClientAdd, cmdClientDel, cmdClientList, cmdClientLink, cmdClientFind, cmdClientStats,
        cmdConfig
    };

    static const char *sCmd[] = {
        "add", "del", "flush", "list", "resolve", "queue", "lookup", "stat", "find",
        "clientadd", "clientdel", "clientlist", "clientlink", "clientfind", "clientstats",
        "config", 0
    };
    int cmd;
    struct NS_SOCKADDR_STORAGE sa;
    struct sockaddr *saPtr = (struct sockaddr *)&sa;
    TCL_SIZE_T argc = objc, argp = 2;
    char tmp[128];
    dnsRecord *drec;
    Tcl_HashEntry *hrec;
    Tcl_HashSearch search;
    unsigned long n, r;
    dnsClient *client = &dnsClientDflt;

    if (objc < 2) {
        Tcl_AppendResult(interp, "wrong # args: should be ns_dns command ?args ...?", 0);
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK)
        return TCL_ERROR;

    switch (cmd) {
    case cmdClientLink:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "clientip clientip2");
            return TCL_ERROR;
        }
        DnsClientLink(Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
        break;

    case cmdClientAdd:
        if (argc < 6) {
            Tcl_WrongNumArgs(interp, 2, objv, "client name type value ?ttl?");
            return TCL_ERROR;
        }
        client = DnsClientFind(Tcl_GetString(objv[2]), saPtr);
        /* Create new client */
        if (client == &dnsClientDflt) {
            client = DnsClientCreate(Tcl_GetString(objv[2]));
            if (client == NULL) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid client address", -1));
                return TCL_ERROR;
            }
        }
        argc--;
        argp++;
        NS_FALL_THROUGH; /* fall through */

    case cmdAdd:
        if (argc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "name type value ?ttl?");
            return TCL_ERROR;
        } else {
            dnsType_t qtype = dnsType(Tcl_GetString(objv[argp + 1]));
            const char *owner = Tcl_GetString(objv[argp]);
            size_t ownerLength = strlen(owner);
            if (ownerLength == 0 || ownerLength > 253) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("record name must contain 1..253 bytes", -1));
                return TCL_ERROR;
            }
            switch (qtype) {
            case DNS_TYPE_A: /* fall through */
            case DNS_TYPE_AAAA:
                if (argc > 6) {
                    Tcl_WrongNumArgs(interp, argp, objv, "name type address ?ttl?");
                    return TCL_ERROR;
                }
                if (qtype == DNS_TYPE_A) {
                    drec = dnsRecordCreateA(Tcl_GetString(objv[argp]), Tcl_GetString(objv[argp + 2]));
                } else {
                    drec = dnsRecordCreateAAAA(Tcl_GetString(objv[argp]), Tcl_GetString(objv[argp + 2]));
                }
                if (drec == NULL) {
                    Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid numeric address for record type", -1));
                    return TCL_ERROR;
                }
                if (argc > 5) {
                    drec->ttl = GetUlong(objv[argp + 3]);
                }
                break;
            case DNS_TYPE_TXT:
                if (argc > 6) {
                    Tcl_WrongNumArgs(interp, argp, objv, "name TXT strings ?ttl?");
                    return TCL_ERROR;
                }
                drec = dnsRecordCreateTXT(interp, Tcl_GetString(objv[argp]), objv[argp + 2]);
                if (drec == NULL) return TCL_ERROR;
                if (argc > 5) drec->ttl = GetUlong(objv[argp + 3]);
                break;
            case DNS_TYPE_MX:
                if (argc < 6) {
                    Tcl_WrongNumArgs(interp, 2, objv, "name type preference value ?ttl?");
                    return TCL_ERROR;
                }
                drec = dnsRecordCreateMX(Tcl_GetString(objv[argp]), GetUshort(objv[argp + 2]),
                                         Tcl_GetString(objv[argp + 3]));
                if (argc > 6) {
                    drec->ttl = GetUlong(objv[argp + 4]);
                }
                break;
            case DNS_TYPE_NAPTR:
                if (argc < 9) {
                    Tcl_WrongNumArgs(interp, 2, objv, "name type order preference flags service regexp ?replace? ?ttl?");
                    return TCL_ERROR;
                }
                drec = dnsRecordCreateNAPTR(Tcl_GetString(objv[argp]),
                                            GetShort(objv[argp + 2]),
                                            GetShort(objv[argp + 3]),
                                            Tcl_GetString(objv[argp + 4]),
                                            Tcl_GetString(objv[argp + 5]),
                                            Tcl_GetString(objv[argp + 6]),
                                            argc > 9 ? Tcl_GetString(objv[argp + 7]) : 0);
                if (argc > 10) {
                    drec->ttl = GetUlong(objv[argp + 8]);
                }
                break;
            case DNS_TYPE_NS:
                drec = dnsRecordCreateNS(Tcl_GetString(objv[argp]), Tcl_GetString(objv[argp + 2]));
                if (argc > 5) {
                    drec->ttl = GetUlong(objv[argp + 3]);
                }
                break;
            case DNS_TYPE_PTR:
                drec = dnsRecordCreatePTR(Tcl_GetString(objv[argp]), Tcl_GetString(objv[argp + 2]));
                if (argc > 5) {
                    drec->ttl = GetUlong(objv[argp + 3]);
                }
                break;
            case DNS_TYPE_CNAME:
                drec = dnsRecordCreateCNAME(Tcl_GetString(objv[argp]), Tcl_GetString(objv[argp + 2]));
                if (argc > 5) {
                    drec->ttl = GetUlong(objv[argp + 3]);
                }
                break;

            case DNS_TYPE_SOA:   /* fall through */
            case DNS_TYPE_WKS:   /* fall through */
            case DNS_TYPE_HINFO: /* fall through */
            case DNS_TYPE_MINFO: /* fall through */
            case DNS_TYPE_SRV:   /* fall through */
            case DNS_TYPE_OPT:   /* fall through */
            case DNS_TYPE_ANY:   /* fall through */
            default:
                Tcl_AppendResult(interp, "wrong record type, should be A,AAAA,TXT,MX,PTR,CNAME,NS,NAPTR", 0);
                return TCL_ERROR;
            }
            dnsRecordUpdate(drec);
            dnsRecordCache(client, &drec);
        }
        break;

    case cmdClientDel:
        if (argc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "client name type ?value?");
            return TCL_ERROR;
        }
        client = DnsClientFind(Tcl_GetString(objv[2]), saPtr);
        /* Ignore unknown clients */
        if (client == &dnsClientDflt) {
            break;
        }
        argc--;
        argp++;
        NS_FALL_THROUGH; /* fall through */

    case cmdDel:
        if (argc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name type ?value?");
            return TCL_ERROR;
        } else {
            Ns_RWLockWrLock(&client->lock);
            if ((hrec = Tcl_FindHashEntry(&client->list, Tcl_GetString(objv[argp])))) {
                dnsType_t type = dnsType(Tcl_GetString(objv[argp + 1]));
                dnsRecord *list = Tcl_GetHashValue(hrec);
                for (drec = list; drec != NULL;) {
                    dnsRecord *next = drec->next;
                    if (drec->type == type) {
                        if (type == DNS_TYPE_NAPTR && drec->nsize >= 0
                            && drec->nsize < 256 && client->rstats[drec->nsize] > 0) {
                            client->rstats[drec->nsize]--;
                        }
                        dnsRecordRemove(&list, drec);
                        dnsRecordFree(drec);
                    }
                    drec = next;
                }
                if (list == NULL) {
                    Tcl_DeleteHashEntry(hrec);
                    client->rcount--;
                } else {
                    Tcl_SetHashValue(hrec, list);
                }
            }
            Ns_RWLockUnlock(&client->lock);
        }
        break;

    case cmdClientFind:
        if (argc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "client name");
            return TCL_ERROR;
        }
        client = DnsClientFind(Tcl_GetString(objv[2]), saPtr);
        /* Ignore unknown clients */
        if (client == &dnsClientDflt) {
            break;
        }
        argc--;
        argp++;
        NS_FALL_THROUGH; /* fall through */

    case cmdFind:
        if (argc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        Ns_RWLockWrLock(&client->lock);
        if ((hrec = Tcl_FindHashEntry(&client->list, Tcl_GetString(objv[argp])))) {
            Tcl_SetObjResult(interp, dnsRecordCreateTclObj(interp, Tcl_GetHashValue(hrec)));
        }
        Ns_RWLockUnlock(&client->lock);
        break;

    case cmdClientStats:{
        char *ptr, *stats;

        Ns_RWLockWrLock(&dnsClientLock);
        hrec = Tcl_FirstHashEntry(&dnsClientList, &search);
        while (hrec) {
            client = Tcl_GetHashValue(hrec);
            stats = (char *) Tcl_HashStats(&client->list);
            //addr.s_addr = (unsigned long) Tcl_GetHashKey(&dnsClientList, hrec);
            //Tcl_AppendElement(interp, ns_inet_ntoa(addr));
            Tcl_AppendElement(interp, Tcl_GetHashKey(&dnsClientList, hrec));
            sprintf(tmp, "%lu", client->rcount);
            Tcl_AppendElement(interp, tmp);
            for (ptr = stats; *ptr; ptr++) {
                if (*ptr == '\n') {
                    *ptr = ',';
                }
            }
            Tcl_AppendElement(interp, stats);
            hrec = Tcl_NextHashEntry(&search);
            Tcl_Free(stats);
        }
        Ns_RWLockUnlock(&dnsClientLock);
        break;
    }

    case cmdClientList:
        Ns_RWLockWrLock(&dnsClientLock);
        hrec = Tcl_FirstHashEntry(&dnsClientList, &search);
        while (hrec) {
            //addr.s_addr = (unsigned long) Tcl_GetHashKey(&dnsClientList, hrec);
            //Tcl_AppendElement(interp, ns_inet_ntoa(addr));
            Tcl_AppendElement(interp, Tcl_GetHashKey(&dnsClientList, hrec));
            hrec = Tcl_NextHashEntry(&search);
        }
        Ns_RWLockUnlock(&dnsClientLock);
        break;

    case cmdList: {
        Tcl_Obj *list = Tcl_NewListObj(0, 0);
        if (objc > 2) {
            client = DnsClientFind(Tcl_GetString(objv[2]), saPtr);
        }
        Ns_RWLockRdLock(&client->lock);
        hrec = Tcl_FirstHashEntry(&client->list, &search);
        while (hrec) {
            Tcl_ListObjAppendElement(interp, list, dnsRecordCreateTclObj(interp, Tcl_GetHashValue(hrec)));
            hrec = Tcl_NextHashEntry(&search);
        }
        Ns_RWLockUnlock(&client->lock);
        Tcl_SetObjResult(interp, list);
        break;
    }

    case cmdFlush:
        if (objc > 2) {
            client = DnsClientFind(Tcl_GetString(objv[2]), saPtr);
            /* Ignore unknown clients */
            if (client == &dnsClientDflt) {
                break;
            }
        }
        Ns_RWLockWrLock(&client->lock);
        hrec = Tcl_FirstHashEntry(&client->list, &search);
        while (hrec) {
            drec = Tcl_GetHashValue(hrec);
            dnsRecordDestroy(&drec);
            Tcl_DeleteHashEntry(hrec);
            hrec = Tcl_NextHashEntry(&search);
        }
        client->rcount = 0;
        memset(client->rstats, 0, sizeof(client->rstats));
        Ns_RWLockUnlock(&client->lock);
        break;

    case cmdStat:
        {
            int i;
            for (n = 0, r = 0, i = 0; i < dnsThreads; i++) {
                n += dnsQueues[i].size;
                r += dnsQueues[i].requests;
                sprintf(tmp, "size%d %lu maxsize%d %lu rtime%d %lu wtime%d %lu requests%d %lu ",
                        i, dnsQueues[i].size, i, dnsQueues[i].maxsize,
                        i, dnsQueues[i].rtime, i, dnsQueues[i].wtime, i, dnsQueues[i].requests);
                Tcl_AppendResult(interp, tmp, 0);
            }
            sprintf(tmp, "total %lu requests %lu", n, r);
            Tcl_AppendResult(interp, tmp, 0);
            break;
        }

    case cmdQueue:{
        char buf[255];
        dnsRequest *req;

        Ns_MutexLock(&dnsProxyMutex);
        for (req = dnsProxyQueue; req; req = req->next) {
            snprintf(buf, sizeof(buf), "%u %s", req->req->id, req->req->qdlist->name);
            Tcl_AppendElement(interp, buf);
        }
        Ns_MutexUnlock(&dnsProxyMutex);
        break;
    }

    case cmdResolve:
    case cmdLookup: {
        int             details = 0, jointxt = 0, port = 53;
        char           *name = NULL, *type = NULL;
        const char     *server = "127.0.0.1";
        Ns_Time        *timeout = NULL;
        dnsType_t       qtype = 0;
        dnsPacket      *reply;
        dnsQueryStatus status;
        Tcl_Obj      **normalized = NULL;
        Tcl_Obj *const *queryv = objv;
        bool            legacy = cmd == cmdResolve && objc > 3 && Tcl_GetString(objv[2])[0] != '-';
        Ns_ObjvSpec lookupOpts[] = {
            {"-details", Ns_ObjvBool, &details, INT2PTR(NS_TRUE)},
            {"-jointxt", Ns_ObjvBool, &jointxt, INT2PTR(NS_TRUE)},
            {"-timeout", Ns_ObjvTime, &timeout, NULL},
            {"--", Ns_ObjvBreak, NULL, NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec resolveOpts[] = {
            {"-details", Ns_ObjvBool, &details, INT2PTR(NS_TRUE)},
            {"-jointxt", Ns_ObjvBool, &jointxt, INT2PTR(NS_TRUE)},
            {"-timeout", Ns_ObjvTime, &timeout, NULL},
            {"-type", Ns_ObjvString, &type, NULL},
            {"-server", Ns_ObjvString, &server, NULL},
            {"-port", Ns_ObjvInt, &port, NULL},
            {"--", Ns_ObjvBreak, NULL, NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec lookupArgs[] = {
            {"name", Ns_ObjvString, &name, NULL},
            {"?type", Ns_ObjvString, &type, NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec resolveArgs[] = {
            {"name", Ns_ObjvString, &name, NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ReturnCode parsed;

        /* Retain hostname-first resolve calls; all validation stays in
         * Ns_ParseObjv. Only move the positional hostname after the options. */
        if (legacy) {
            TCL_SIZE_T i;

            normalized = ns_malloc((size_t)objc * sizeof(Tcl_Obj *));
            normalized[0] = objv[0];
            normalized[1] = objv[1];
            for (i = 3; i < objc; i++) {
                normalized[i - 1] = objv[i];
            }
            normalized[objc - 1] = objv[2];
            queryv = normalized;
        }
        parsed = Ns_ParseObjv(cmd == cmdLookup ? lookupOpts : resolveOpts,
                              cmd == cmdLookup ? lookupArgs : resolveArgs,
                              interp, 2, objc, queryv);
        ns_free(normalized);
        if (parsed != NS_OK) {
            return TCL_ERROR;

        } else if (port < 1 || port > 65535) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("port must be 1..65535", -1));
            return TCL_ERROR;

        } else if (timeout != NULL && (!legacy || details)
            && (timeout->sec < 0 || timeout->usec < 0)) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("timeout must be nonnegative", -1));
            return TCL_ERROR;
        }

        if (type != NULL) {
            qtype = dnsType(type);
        }
        if (cmd == cmdLookup) {
            reply = dnsLookupDetailed(name, qtype, timeout, &status);

        } else if (legacy && !details && timeout != NULL) {
            /* Historical resolve timeouts were integer seconds per attempt. */
            if (timeout->sec > INT_MAX || timeout->sec < INT_MIN) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("legacy resolve timeout out of range", -1));
                return TCL_ERROR;
            }
            reply = dnsResolveAt(name, qtype, server, (unsigned short)port, (int)timeout->sec, 3);
            status = DNS_QUERY_NETWORK; /* Legacy failure still returns empty. */
        } else {
            reply = dnsResolveDetailed(name, qtype, server, (unsigned short)port, timeout, &status);
        }

        if (reply != NULL) {
            Tcl_Obj    *result = details ? Tcl_NewDictObj() : Tcl_NewListObj(0, NULL);
            dnsRecord  *sections[] = {reply->anlist, reply->nslist, reply->arlist};
            const char *keys[] = {"answer", "authority", "additional"};

            if (details) {
                unsigned int rcode = DNS_GET_RCODE(reply->u);
                dnsRecord   *record;

                for (record = reply->arlist; record != NULL; record = record->next) {
                    if (record->type == DNS_TYPE_OPT) rcode |= ((record->ttl >> 24) & 255u) << 4;
                }
                Tcl_DictObjPut(interp, result, Tcl_NewStringObj("rcode", -1), Tcl_NewIntObj((int)rcode));
                Tcl_DictObjPut(interp, result, Tcl_NewStringObj("truncated", -1), Tcl_NewBooleanObj(DNS_GET_TC(reply->u) != 0));
            }
            for (size_t i = 0; i < 3; i++) {
                Tcl_Obj *records = dnsRecordCreateTclObjEx(interp, sections[i], jointxt != 0);

                if (details) Tcl_DictObjPut(interp, result, Tcl_NewStringObj(keys[i], -1), records);
                else Tcl_ListObjAppendElement(interp, result, records);
            }
            Tcl_SetObjResult(interp, result);
            dnsPacketFree(reply, 0);

        } else if (details) {
            const char *message = "DNS network operation failed";

            switch (status) {
            case DNS_QUERY_TIMEOUT:
                Tcl_SetErrorCode(interp, "NS_TIMEOUT", NS_SENTINEL);
                message = "DNS query timed out";
                break;
            case DNS_QUERY_MALFORMED:
            case DNS_QUERY_MISMATCH:
            case DNS_QUERY_TRUNCATED:
                Tcl_SetErrorCode(interp, "NSDNS", "PROTOCOL",
                                 status == DNS_QUERY_MALFORMED ? "MALFORMED" :
                                 status == DNS_QUERY_MISMATCH ? "MISMATCH" : "TRUNCATED", NS_SENTINEL);
                message = "DNS response was malformed, mismatched or truncated";
                break;
            case DNS_QUERY_NOSERVER:
                Tcl_SetErrorCode(interp, "NSDNS", "CONFIG", "NO_NAMESERVER", NS_SENTINEL);
                message = "No DNS nameserver is configured or available";
                break;
            case DNS_QUERY_OK:
            case DNS_QUERY_NETWORK:
                Tcl_SetErrorCode(interp, "NSDNS", "NETWORK", NS_SENTINEL);
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewStringObj(message, -1));
            return TCL_ERROR;
        }
        break;
    }

    case cmdConfig:
        {
            TCL_SIZE_T i;

            for (i = 2; i < objc - 1; i += 2) {
                char *key = Tcl_GetString(objv[i]);
                if (!strcmp("ttl", key) ||
                    !strcmp("debug", key) ||
                    !strcmp("flags", key) ||
                    !strcmp("timeout", key) ||
                    !strcmp("retry", key) ||
                    !strcmp("failuretimeout", key)) {
                    dnsInit(key, strtol(Tcl_GetString(objv[i + 1]), NULL, 10));
                } else if (!strcmp("nameserver", key)) {
                    dnsInit(key, Tcl_GetString(objv[i + 1]), (char *)NULL);
                }
            }
            break;
        }
    }
    return TCL_OK;
}

static void DnsQueueListenThread(void *UNUSED(arg))
{
    dnsRequest    *req, buf;
    struct timeval recv_time;
    int            id = 0;

    memset(&buf, 0, sizeof(buf));
    Ns_ThreadSetName("nsdns:thread");

    while (1) {
        socklen_t        socklen = (socklen_t)sizeof(buf.sa);
        struct sockaddr *saPtr = (struct sockaddr *)&(buf.sa);
        char             ipString[NS_IPADDR_SIZE];

        if ((buf.size = recvfrom(dnsUdpSock, buf.buffer, DNS_BUF_SIZE, 0, saPtr, &socklen)) <= 0) {
            Ns_Log(Error, "nsdns: recvfrom error (udp sock %d): %s", dnsUdpSock, strerror(errno));
            continue;
        }
        buf.buffer[buf.size] = 0;
        gettimeofday(&recv_time, 0);

        Ns_Log(DnsdDebug, "nsdns: received %ld bytes from %s", buf.size,
               ns_inet_ntop(saPtr, ipString, sizeof(ipString)));
        /*
         *  Link new job into the queue
         */
        Ns_MutexLock(&dnsQueues[id].lock);
        if ((req = dnsQueues[id].freelist)) {
            dnsQueues[id].freelist = req->next;
            req->next = 0;
        }
        if (req == 0) {
            req = ns_calloc(1, sizeof(dnsRequest));
        }
        memcpy(req, &buf, sizeof(buf));

        req->recv_time = recv_time;
        if (dnsQueues[id].tail) {
            dnsQueues[id].tail->next = req;
        }
        dnsQueues[id].tail = req;
        if (!dnsQueues[id].head) {
            dnsQueues[id].head = req;
        }
        if (++dnsQueues[id].size > dnsQueues[id].maxsize) {
            dnsQueues[id].maxsize = dnsQueues[id].size;
        }
        dnsQueues[id].requests++;
        Ns_CondBroadcast(&dnsQueues[id].cond);
        Ns_MutexUnlock(&dnsQueues[id].lock);
        if (++id >= dnsThreads) {
            id = 0;
        }
    }
}

static void DnsQueueRequestThread(void *arg)
{
    char buf[32];
    dnsQueue *queue;
    dnsRequest *req;
    struct timeval end_time;

    queue = (dnsQueue *) arg;
    sprintf(buf, "nsdns:queue:%d", queue->id);
    Ns_Log(Notice, "Starting thread: %s", buf);
    Ns_ThreadSetName("%s", buf);

    Ns_MutexSetName(&queue->lock, buf);
    Ns_MutexLock(&queue->lock);
    while (1) {
        unsigned long rt, wt;

        while (queue->head == 0) {
            Ns_CondWait(&queue->cond, &queue->lock);
        }
        /*
         *  Unlink first job from the queue
         */
        req = queue->head;
        queue->head = req->next;
        if (queue->tail == req) {
            queue->tail = 0;
        }
        queue->size--;
        Ns_MutexUnlock(&queue->lock);
        rt = wt = 0u;
        gettimeofday(&req->start_time, 0);
        req->sock = dnsUdpSock;
        /* Allocate request structure */
        if ((req->req = dnsParsePacket((unsigned char*)req->buffer, (size_t)req->size))) {
            /* Prepare reply header */
            req->reply = dnsPacketCreateReply(req->req);
            req->client = DnsClientFind(NULL, (struct sockaddr *)&(req->sa));
            switch (dnsRequestHandle(req)) {
            case 1:
                /* Proxy will handle request */
                req = 0;
                break;
            case 0:
                dnsRequestSend(req);
                dnsPacketFree(req->req, 3);
                dnsPacketFree(req->reply, 4);
                /* Update statistics, in milliseconds */
                gettimeofday(&end_time, 0);
                rt = (unsigned long)
                    ((end_time.tv_sec - req->start_time.tv_sec) * 1000 +
                     (end_time.tv_usec - req->start_time.tv_usec) / 1000);
                wt = (unsigned long)
                    ((req->start_time.tv_sec - req->recv_time.tv_sec) * 1000 +
                     (req->start_time.tv_usec - req->recv_time.tv_usec) / 1000);
                break;
            }
        }
        Ns_MutexLock(&queue->lock);
        /* Put request structure back if not handled by proxy */
        if (req != 0) {
            req->next = queue->freelist;
            queue->freelist = req;
        }
        if (rt > queue->rtime) {
            queue->rtime = rt;
        }
        if (wt > queue->wtime) {
            queue->wtime = wt;
        }
    }
}

typedef struct {
    NS_SOCKET sock;
    struct NS_SOCKADDR_STORAGE sa;
} DnsTcpArg;

static bool DnsTcpListen(NS_SOCKET sock, void *UNUSED(si), unsigned int when)
{
    if ((when & NS_SOCK_READ) != 0u) {
        DnsTcpArg *arg = ns_malloc(sizeof(DnsTcpArg));
        socklen_t length = (socklen_t)sizeof(arg->sa);
        arg->sock = Ns_SockAccept(sock, (struct sockaddr *)&arg->sa, &length);
        if (arg->sock == NS_INVALID_SOCKET) {
            ns_free(arg);
            return NS_TRUE;
        }
        Ns_ThreadCreate(DnsTcpThread, arg, 0, NULL);
        return NS_TRUE;
    }
    ns_sockclose(sock);
    return NS_FALSE;
}

static void DnsTcpThread(void *argPtr)
{
    DnsTcpArg arg = *(DnsTcpArg *)argPtr;
    uint16_t wireLength;
    size_t length;
    dnsRequest *req;
    char *buf;

    ns_free(argPtr);
    Ns_SockSetNonBlocking(arg.sock);
    if (dnsRead(arg.sock, &wireLength, sizeof(wireLength)) != sizeof(wireLength)) {
        ns_sockclose(arg.sock);
        return;
    }
    length = ntohs(wireLength);
    buf = ns_malloc(length);
    if (dnsRead(arg.sock, buf, length) != (ssize_t)length
        || (req = dnsRequestCreate(arg.sock, buf, length)) == NULL) {
        ns_free(buf);
        ns_sockclose(arg.sock);
        return;
    }
    ns_free(buf);
    req->flags |= DNS_TCP;
    req->sa = arg.sa;
    req->client = DnsClientFind(NULL, (struct sockaddr *)&req->sa);
    if (dnsRequestHandle(req) != 1) {
        dnsRequestSend(req);
        dnsRequestFree(req);
    }
}

static void DnsProxyThread(void *UNUSED(arg))
{
    ssize_t len;
    time_t now;
    dnsRequest *req;
    char buf[DNS_BUF_SIZE + 1];
    char ipString[NS_IPADDR_SIZE];
    //struct sockaddr_in addr;
    struct NS_SOCKADDR_STORAGE sa;
    struct sockaddr           *saPtr = (struct sockaddr *)&sa;

    Ns_Log(Notice, "nsdns: proxy thread started, proxy %s [%s]:%d FD %d",
           dnsProxyHost, ns_inet_ntop(dnsProxyAddrPtr, ipString, sizeof(ipString)),
           dnsProxyPort, dnsProxySock);

    while (1) {

        Ns_MutexLock(&dnsProxyMutex);
        while (dnsProxyQueue == 0) {
            Ns_CondWait(&dnsProxyCond, &dnsProxyMutex);
        }
        now = time(0);
        for (req = dnsProxyQueue; req != NULL;) {
            if (now - (time_t)req->proxy_time > dnsProxyTimeout) {
                char proxyIpString[NS_IPADDR_SIZE];

                /* First time, prepare for proxying, use our own id sequence to
                 * keep track of forwarded requests */
                if (req->proxy_count == 0) {
                    uint16_t wireId;

                    req->proxy_id = req->req->id;
                    req->req->id = ++dnsID;
                    wireId = htons(req->req->id);
                    memcpy(req->req->buf.data + 2, &wireId, sizeof(wireId));
                }
                /* Reached max request limit, reply with not found code */
                if (req->proxy_count >= dnsProxyRetries) {
                    dnsRequest *next = req->next;
                    if (req->prev == 0) {
                        dnsProxyQueue = req->next;
                    } else {
                        req->prev->next = req->next;
                    }
                    if (req->next != 0) {
                        req->next->prev = req->prev;
                    }
                    DNS_SET_RCODE(req->reply->u, RCODE_SRVFAIL);
                    req->req->qdlist->rcode = RCODE_SRVFAIL;
                    dnsRecordCache(req->client, &req->req->qdlist);
                    dnsRequestSend(req);
                    dnsRequestFree(req);
                    req = next;
                    continue;
                }
                /* Repeat forwarding request */

                Ns_Log(DnsdDebug, "sending proxy request to [%s]:%d",
                       ns_inet_ntop(dnsProxyAddrPtr, proxyIpString, sizeof(proxyIpString)),
                       Ns_SockaddrGetPort(dnsProxyAddrPtr));

                sendto(dnsProxySock,
                       req->req->buf.data + 2,
                       req->req->buf.size, 0,
                       dnsProxyAddrPtr, Ns_SockaddrGetSockLen(dnsProxyAddrPtr));
                req->proxy_count++;
                req->proxy_time = (unsigned long)now;
                dnsPacketLog(req->req, 4, "Sending to proxy:");
            }
            req = req->next;
        }
        Ns_MutexUnlock(&dnsProxyMutex);
        if (Ns_SockWait(dnsProxySock, NS_SOCK_READ, 1) != NS_OK) {
            continue;
        }

        {
            socklen_t addressLength = sizeof(sa);
            len = recvfrom(dnsProxySock, buf, DNS_BUF_SIZE, 0, saPtr, &addressLength);
        }
        if (len < DNS_HEADER_LEN) continue;

        Ns_Log(DnsdDebug, "receive reply from [%s]:%d, len = %ld, isproxy %d",
               ns_inet_ntop(saPtr, ipString, sizeof(ipString)),
               Ns_SockaddrGetPort(saPtr), len,
               Ns_SockaddrSameIP(saPtr, dnsProxyAddrPtr));

        if (len < 0
            || Ns_SockaddrSameIP(saPtr, dnsProxyAddrPtr) == NS_FALSE
            || Ns_SockaddrGetPort(saPtr) != Ns_SockaddrGetPort(dnsProxyAddrPtr)
            ) {
            if (errno != 0 && errno != EAGAIN && errno != EINTR) {
                char errorIpString[NS_IPADDR_SIZE];

                Ns_Log(Error, "nsdns: recvfrom error %s: %s",
                       ns_inet_ntop(saPtr, errorIpString, sizeof(errorIpString)),
                       strerror(errno));
            }
            continue;
        }

        Ns_Log(DnsdDebug, "DnsProxyThread: received %zd bytes from %s", len,
               ns_inet_ntop(dnsProxyAddrPtr, ipString, sizeof(ipString)));

        Ns_MutexLock(&dnsProxyMutex);
        for (req = dnsProxyQueue; req != NULL; req = req->next) {
          /* Find request with received ID and remove from the queue */
            uint16_t wireId;
            memcpy(&wireId, buf, sizeof(wireId));

            if (req->req->id == ntohs(wireId)) {
                if (req->prev == 0) {
                    dnsProxyQueue = req->next;
                } else {
                    req->prev->next = req->next;
                }
                if (req->next != 0) {
                    req->next->prev = req->prev;
                }
                break;
            }
        }
        Ns_Log(DnsdDebug, "DnsProxyThread: found request %p", (void *)req);

        Ns_MutexUnlock(&dnsProxyMutex);
        /* Forward reply back to the client and cache locally */
        if (req != NULL) {
            uint16_t wireId = htons(req->proxy_id);
            memcpy(buf, &wireId, sizeof(wireId));
            dnsPacketFree(req->reply, 1);
            assert(len >= 0);
            if ((req->reply = dnsParsePacket((unsigned char*)buf, (size_t)len))) {
                dnsPacketLog(req->reply, 6, "Proxy reply received:");
                if (DNS_GET_TC(req->reply->u) && (req->flags & DNS_TCP) != 0u) {
                    dnsPacket *complete;
                    /* Re-encode to include the TCP length prefix. */
                    dnsEncodePacket(req->req);
                    complete = dnsResolveTcp(req->req, dnsProxyHost,
                                             (unsigned short)dnsProxyPort, dnsProxyTimeout);
                    if (complete != NULL) {
                        dnsPacketFree(req->reply, 0);
                        req->reply = complete;
                        req->reply->id = req->proxy_id;
                    }
                }
                dnsRequestSend(req);
                /* A truncated answer is not a complete cache entry. */
                if (!DNS_GET_TC(req->reply->u)) {
                    dnsRecordCache(req->client, &req->reply->anlist);
                    dnsRecordCache(req->client, &req->reply->nslist);
                    dnsRecordCache(req->client, &req->reply->arlist);
                }
            }
            dnsRequestFree(req);
        }
    }
}

static ssize_t dnsRead(int sock, void *vbuf, size_t len)
{
    ssize_t nread;
    char *buf = (char *) vbuf;
    Ns_Time timeout = { dnsReadTimeout, 0 };

    nread = (ssize_t)len;
    while (len > 0) {
        ssize_t n = Ns_SockRecv(sock, buf, len, &timeout);

        if (n <= 0) {
            return -1;
        } else {
            len = len - (size_t)n;
            buf += n;
        }
    }
    return nread;
}

static ssize_t dnsWrite(int sock, void *vbuf, size_t len)
{
    ssize_t nwrote;
    char *buf;
    Ns_Time timeout = { dnsWriteTimeout, 0 };

    nwrote = (ssize_t)len;
    buf = vbuf;
    while (len > 0) {
        ssize_t n = Ns_SockSend(sock, buf, len, &timeout);

        if (n <= 0) {
            return -1;
        } else {
            len = len - (size_t)n;
            buf += n;
        }
    }
    return nwrote;
}

static void *dnsRequestCreate(int sock, char *buf, size_t len)
{
    dnsPacket *pkt;
    dnsRequest *req;

    if (!(pkt = dnsParsePacket((unsigned char*)buf, len))) {
        return 0;
    }
    /* Allocate request structure */
    req = ns_calloc(1, sizeof(dnsRequest));
    req->sock = sock;
    req->req = pkt;
    /* Prepare reply header */
    req->reply = dnsPacketCreateReply(req->req);
    /* Ns_Log(Debug,"ralloc[%d]: %x",getpid(),req); */
    return req;
}

static void dnsRequestFree(dnsRequest *req)
{
    if (req == 0) {
        return;
    }
    /* Ns_Log(Debug,"rfree[%d]: %x, %x %x",getpid(),req,req->req,req->reply); */
    if ((req->flags & DNS_TCP) != 0u) ns_sockclose(req->sock);
    dnsPacketFree(req->req, 3);
    dnsPacketFree(req->reply, 4);
    ns_free(req);
}

static int dnsRequestFind(dnsRequest *req, dnsRecord *qlist, unsigned int depth)
{
    ssize_t    nsize;
    char       domain[255], *ptr, *str;
    time_t     now = time(0);
    dnsRecord *qrec, *qcache, *ncache, *qstart, *qend;

    if (depth > 16) return 0;
    for (qrec = qlist; qrec; qrec = qrec->next) {
        Tcl_HashEntry *nrec, *hrec = NULL;

        if (qrec->name == 0) {
            continue;
        }
        dnsRecordLog(qrec, 9, "Searching for:");
        nsize = qrec->nsize;
        switch (qrec->type) {
        case DNS_TYPE_NAPTR:
            /*
             * Calculate how many dots we have in the name
             */
            ptr = qrec->name;
            while (*ptr) {
                /* Search only those names that we have in cache */
                if (nsize >= 256 || req->client->rstats[nsize]) {
                    if ((hrec = Tcl_FindHashEntry(&req->client->list, ptr))) {
                        break;
                    }
                }
                for (; *ptr && *ptr != '.'; ptr++, nsize--);
                if (*ptr == '.') {
                    ptr++;
                    nsize--;
                }
            }
            if (hrec == 0) {
                continue;
            }
            break;
        case DNS_TYPE_A:     /* fall through */
        case DNS_TYPE_NS:    /* fall through */
        case DNS_TYPE_CNAME: /* fall through */
        case DNS_TYPE_SOA:   /* fall through */
        case DNS_TYPE_WKS:   /* fall through */
        case DNS_TYPE_PTR:   /* fall through */
        case DNS_TYPE_HINFO: /* fall through */
        case DNS_TYPE_MINFO: /* fall through */
        case DNS_TYPE_MX:    /* fall through */
        case DNS_TYPE_TXT:   /* fall through */
        case DNS_TYPE_AAAA:  /* fall through */
        case DNS_TYPE_SRV:   /* fall through */
        case DNS_TYPE_OPT:   /* fall through */
        case DNS_TYPE_ANY:   /* fall through */
        default:
            /* Exact and wildcard search */
            if (!(hrec = Tcl_FindHashEntry(&req->client->list, qrec->name))) {
                snprintf(domain, sizeof(domain) - 1, "*.%s", qrec->name);
                if (!(hrec = Tcl_FindHashEntry(&req->client->list, domain))) {
                    if (!(ptr = strchr(qrec->name, '.'))) {
                        continue;
                    }
                    snprintf(domain, sizeof(domain) - 1, "*%s", ptr);
                    if (!(hrec = Tcl_FindHashEntry(&req->client->list, domain))) {
                        continue;
                    }
                }
            }
        }
        if (!(qcache = Tcl_GetHashValue(hrec))) {
            continue;
        }
        dnsRecordLog(qcache, 5, "Found cache:");
        qend = 0;
        qstart = qcache;
        while (qcache) {
            if (qrec->type == DNS_TYPE_ANY ||
                qcache->type == DNS_TYPE_CNAME ||
                qcache->type == qrec->type) {
                /*
                 * This is cached record, verify expiration and remove
                 * from the cache if expired
                 */
                if (qcache->timestamp
                    && qcache->ttl
                    && qcache->timestamp + qcache->ttl < (unsigned long)now
                    ) {
                    dnsRecord *next = qcache->next;

                    dnsRecordLog(qcache, 2, "Record expired:");
                    if (qcache->prev != 0) {
                        qcache->prev->next = qcache->next;
                    }
                    if (qcache->next != 0) {
                        qcache->next->prev = qcache->prev;
                    }
                    if (!qcache->next && !qcache->prev) {
                        dnsRecordFree(qcache);
                        Tcl_DeleteHashEntry(hrec);
                        qstart = qend = 0;
                        break;
                    }
                    /* First item deleted, update cache entry value */
                    if (qcache == qstart) {
                        if ((qstart = next)) {
                            qstart->prev = 0;
                            Tcl_SetHashValue(hrec, qstart);
                        }
                    }
                    dnsRecordFree(qcache);
                    qcache = next;
                    continue;
                }
                switch (qcache->type) {
                case DNS_TYPE_CNAME: {
                    dnsRecord *target = dnsRecordCreate(NULL);
                    target->name = ns_strdup(qcache->data.name);
                    target->nsize = (short)strlen(target->name);
                    target->type = qrec->type;
                    target->class = DNS_CLASS_INET;
                    dnsPacketAddRecord(req->reply, &req->reply->anlist,
                                       &req->reply->ancount, dnsRecordCreate(qcache));
                    if (qrec->type != DNS_TYPE_CNAME) dnsRequestFind(req, target, depth + 1);
                    dnsRecordFree(target);
                    break;
                }

                case DNS_TYPE_NS:
                    if (qrec->type == DNS_TYPE_NS)
                        dnsPacketAddRecord(req->reply, &req->reply->anlist, &req->reply->ancount,
                                           dnsRecordCreate(qcache));
                    else
                        dnsPacketAddRecord(req->reply, &req->reply->nslist, &req->reply->nscount,
                                           dnsRecordCreate(qcache));

                    /* Put IP address of the nameserver into additional section */
                    if ((nrec = Tcl_FindHashEntry(&req->client->list, qcache->data.name))) {
                        for (ncache = Tcl_GetHashValue(nrec); ncache; ncache = ncache->next) {
                            if ( ncache->type == DNS_TYPE_A || ncache->type == DNS_TYPE_AAAA ) {
                                dnsPacketAddRecord(req->reply, &req->reply->arlist, &req->reply->arcount,
                                                   dnsRecordCreate(ncache));
                            }
                        }
                    }
                    break;

                case DNS_TYPE_NAPTR:
                    /*
                     * If we found record using wildcard, we have to
                     * replace shorter phone in the regexp with
                     * requested from the query.
                     */
                    if ((dnsFlags & DNS_NAPTR_REGEXP) != 0
                        && nsize < qrec->nsize
                        && qcache->data.naptr->regexp_p1
                        ) {
                        /* Create record without regexp, we will build it manually */
                        ptr = qcache->data.naptr->regexp;
                        qcache->data.naptr->regexp = 0;
                        ncache = dnsRecordCreate(qcache);
                        qcache->data.naptr->regexp = ptr;
                        /* Build regexp from 3 parts */
                        ncache->data.naptr->regexp = str = ns_malloc((size_t)qrec->nsize + strlen(ptr) + 1u);
                        /* Before phone */
                        for (ptr = qcache->data.naptr->regexp; ptr <= qcache->data.naptr->regexp_p1;) {
                            *str++ = *ptr++;
                        }
                        /* Phone itself */
                        for (ptr = &qrec->name[qrec->nsize - 1]; ptr >= qrec->name; ptr--) {
                            if (isdigit(*ptr) && (ptr == qrec->name || *(ptr - 1) == '.')) {
                                *str++ = *ptr;
                            }
                        }
                        /* After phone */
                        for (ptr = qcache->data.naptr->regexp_p2; *ptr;) {
                            *str++ = *ptr++;
                        }
                        *str = 0;
                        dnsPacketAddRecord(req->reply, &req->reply->anlist, &req->reply->ancount, ncache);
                        break;
                    }
                    NS_FALL_THROUGH; /* fall through */

                case DNS_TYPE_A:     NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_SOA:   NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_WKS:   NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_PTR:   NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_HINFO: NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_MINFO: NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_MX:    NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_TXT:   NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_AAAA:  NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_SRV:   NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_OPT:   NS_FALL_THROUGH; /* fall through */
                case DNS_TYPE_ANY:   NS_FALL_THROUGH; /* fall through */
                default:
                    /* Exact match */
                    dnsPacketAddRecord(req->reply, &req->reply->anlist, &req->reply->ancount, dnsRecordCreate(qcache));
                }

                dnsRecordLog(qcache, 4, "Record matched:");
                /* Use cached rcode */
                if (qcache->rcode != 0) {
                    DNS_SET_RCODE(req->reply->u, qcache->rcode);
                }
            }
            qend = qcache;
            qcache = qcache->next;
        }

        /* Do round-robin rotation if we have multiple records */
        if (req->reply->ancount && qend && qstart && qend != qstart) {
            qcache = qstart->next;
            qcache->prev = 0;
            qend->next = qstart;
            qstart->prev = qend;
            qstart->next = 0;
            Tcl_SetHashValue(hrec, qcache);
        }
    }

    return req->reply->ancount || req->reply->nscount;
}

static int dnsRequestHandle(dnsRequest *req)
{
    dnsPacketLog(req->req, 1, "Received request from client=%s", req->client->ipaddr);

    switch (DNS_GET_OPCODE(req->req->u)) {
    case OPCODE_QUERY:
        Ns_RWLockWrLock(&req->client->lock);
        dnsRequestFind(req, req->req->qdlist, 0);
        Ns_RWLockUnlock(&req->client->lock);
        /* No records found */
        if (!req->reply->ancount && !req->reply->nscount) {
            /* Put request into proxy queue */
            if (dnsProxyHost != 0) {
                Ns_MutexLock(&dnsProxyMutex);
                req->prev = 0;
                req->next = dnsProxyQueue;
                if (req->next != 0) {
                    req->next->prev = req;
                }
                dnsProxyQueue = req;
                Ns_CondBroadcast(&dnsProxyCond);
                Ns_MutexUnlock(&dnsProxyMutex);
                return 1;
            }
            /* Default host */
            if (dnsDefaultHost != NULL) {
                dnsRecord *query = req->req->qdlist, *record = NULL;
                if (query->type == DNS_TYPE_A) {
                    record = dnsRecordCreateA(query->name, dnsDefaultHost);
                } else if (query->type == DNS_TYPE_AAAA) {
                    record = dnsRecordCreateAAAA(query->name, dnsDefaultHost);
                }
                if (record != NULL) {
                    dnsPacketAddRecord(req->reply, &req->reply->anlist, &req->reply->ancount, record);
                    return 0;
                }
            }
            /* Otherwise reply with not found reply code */
            DNS_SET_RCODE(req->reply->u, RCODE_NXDOMAIN);
        }
        break;

    default:
        /* Not supported request */
        DNS_SET_RCODE(req->reply->u, RCODE_QUERYERR);
    }
    return 0;
}

static ssize_t dnsRequestSend(dnsRequest *req)
{
    ssize_t rc;
    char ipString[NS_IPADDR_SIZE];

    size_t limit = 65535;

    if ((req->flags & DNS_TCP) == 0u) {
        dnsRecord *opt;
        limit = 512;
        for (opt = req->req->arlist; opt != NULL; opt = opt->next) {
            if (opt->type == DNS_TYPE_OPT) {
                limit = opt->class < 512 ? 512 : opt->class;
                if (limit > 65507) limit = 65507;
                break;
            }
        }
    }
    dnsEncodePacketLimit(req->reply, limit);
    /* TCP connection requires packet length before the reply packet */
    if ((req->flags & DNS_TCP) != 0u) {
        Ns_Log(DnsdDebug, "send reply via TCP");
        rc = dnsWrite(req->sock, req->reply->buf.data, req->reply->buf.size + 2);
        dnsPacketLog(req->reply, 5, "Send TCP:");
    } else {
        struct sockaddr *saPtr = (struct sockaddr *)&(req->sa);

        Ns_Log(DnsdDebug, "send reply via UDP to [%s]:%d",
               ns_inet_ntop(saPtr, ipString, sizeof(ipString)),
               Ns_SockaddrGetPort(saPtr));
        rc = sendto(req->sock,
                    req->reply->buf.data + 2,
                    req->reply->buf.size, 0, saPtr, Ns_SockaddrGetSockLen(saPtr));
        dnsPacketLog(req->reply, 5, "Send UDP:");
    }
    return rc;
}

static void dnsRecordCache(dnsClient *client, dnsRecord **list)
{
    int flag;
    dnsRecord *drec, *hlist;
    time_t now = time(0);

    while (*list) {
            Tcl_HashEntry *hrec;

        drec = *list;
        *list = drec->next;
        if (drec->type != DNS_TYPE_A && drec->type != DNS_TYPE_AAAA
            && drec->type != DNS_TYPE_TXT && drec->type != DNS_TYPE_CNAME
            && drec->type != DNS_TYPE_NS && drec->type != DNS_TYPE_PTR
            && drec->type != DNS_TYPE_MX && drec->type != DNS_TYPE_SOA
            && drec->type != DNS_TYPE_NAPTR) {
            dnsRecordFree(drec);
            continue;
        }
        drec->timestamp = (unsigned long)now;
        drec->next = drec->prev = 0;
        /*
         * Cache only if record has ttl and its ttl is less than
         * configured, this is to keep cached records longer.
         */
        if (drec->ttl && drec->ttl < dnsCacheTTL) {
            drec->ttl = dnsCacheTTL;
        }
        Ns_RWLockWrLock(&client->lock);
        hrec = Tcl_CreateHashEntry(&client->list, drec->name, &flag);
        if (flag != 0) {
            Tcl_SetHashValue(hrec, drec);
            client->rcount++;
        } else {
            hlist = Tcl_GetHashValue(hrec);
            if (!dnsRecordSearch(hlist, drec, 1)) {
                if ((drec->next = hlist)) {
                    hlist->prev = drec;
                }
                Tcl_SetHashValue(hrec, drec);
            } else {
                dnsRecordFree(drec);
                Ns_RWLockUnlock(&client->lock);
                continue;
            }
        }
        if (drec->type == DNS_TYPE_NAPTR) {
            /*
             * Update route statistics, mark that we have routes with
             * that length in the cache
             */
            if (drec->nsize >= 0 && drec->nsize < 256) {
                client->rstats[drec->nsize]++;
            }
        }
        Ns_RWLockUnlock(&client->lock);
    }
}

static dnsClient *DnsClientCreate(char *host)
{
    int new;
    dnsClient *client;
    Tcl_HashEntry *entry;
    struct NS_SOCKADDR_STORAGE sa;
    struct sockaddr *saPtr = (struct sockaddr *)&sa;
    char ipString[NS_IPADDR_SIZE];

    if (DnsClientResolve(host, saPtr) == NS_ERROR) {
        Ns_Log(Error, "DnsClientAdd: unable to resolve %s", host);
        return NULL;
    }

    ns_inet_ntop(saPtr, ipString, sizeof(ipString));
    Ns_Log(Notice, "DnsClientAdd: <%s> resolved to %s", host, ipString);

    Ns_RWLockWrLock(&dnsClientLock);
    entry = Tcl_CreateHashEntry(&dnsClientList, ipString, &new);

    if (new > 0) {
        client = ns_calloc(1, sizeof(dnsClient));
        strcpy(client->ipaddr, ipString);

        Ns_RWLockInit(&client->lock);
        Tcl_InitHashTable(&client->list, TCL_STRING_KEYS);
        Tcl_SetHashValue(entry, (ClientData) client);
    }
    client = Tcl_GetHashValue(entry);
    Ns_RWLockUnlock(&dnsClientLock);
    return client;
}

static dnsClient *DnsClientFind(char *host, struct sockaddr *saPtr)
{
    dnsClient *client;
    Tcl_HashEntry *entry;
    char ipString[NS_IPADDR_SIZE];

    if (host != NULL && DnsClientResolve(host, saPtr) == NS_ERROR) {
        Ns_Log(Error, "DnsClientClear: unable to resolve %s", host);
        return &dnsClientDflt;
    }
    ns_inet_ntop(saPtr, ipString, sizeof(ipString));

    Ns_RWLockRdLock(&dnsClientLock);
    entry = Tcl_FindHashEntry(&dnsClientList, ipString);
    Ns_RWLockUnlock(&dnsClientLock);
    /*fprintf(stderr, "DnsClientFind => ipString <%s> -> entry %p\n", ipString, (void *)entry);*/
    if (entry != NULL) {
        client = Tcl_GetHashValue(entry);
        if (client->link != 0) {
            client = client->link;
        }
        return client;
    } else {

        Ns_Log(Warning, "Dns client [%s] not found, returning default address", ipString);
#if 0
        {
            Tcl_HashSearch  search;
            Tcl_HashEntry  *hPtr;

            hPtr = Tcl_FirstHashEntry(&dnsClientList, &search);
            while (hPtr != NULL) {
                fprintf(stderr, "... client entry <%s>\n", Tcl_GetHashKey(&dnsClientList, hPtr));
                hPtr = Tcl_NextHashEntry(&search);
            }
            fprintf(stderr, "... DONE\n");
        }
#endif
    }
    return &dnsClientDflt;
}

static void DnsClientLink(char *host, char *host2)
{
    dnsClient *client, *client2;

    if ((client = DnsClientCreate(host)) && (client2 = DnsClientCreate(host2))) {
        client2->link = client;
    }
}

static int DnsClientResolve(const char *host, struct sockaddr *saPtr)
{
    if (host == NULL) {
        host = Ns_InfoHostname();
    }
    if (Ns_GetSockAddr(saPtr, host, 0) != NS_OK) {
        return NS_ERROR;
    }
    return NS_OK;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
