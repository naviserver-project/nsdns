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
 *   NaviServer DNS support - module file
 *
 *   Author Vlad Seryakov vlad@crystalballinc.com
 *   Gustaf Neumann neumann@wu.ac.at
 *
 */
#define USE_TCL8X
#include "ns.h"
#include "dns.h"

#define DNS_BUFSIZE 65535

typedef struct _dnsServer {
    struct _dnsServer *next;
    char *name;
    //struct NS_SOCKADDR_STORAGE sa;
    unsigned long fail_time;
    unsigned long fail_count;
} dnsServer;

int dnsDebug = 0;
unsigned long dnsTTL = 86400u;
unsigned int dnsFlags = 0u;

static Ns_Mutex dnsMutex;
static dnsServer *dnsServers = 0;
static int dnsResolverRetries = 3;
static unsigned short dnsResolverPort = 53;
static int dnsResolverTimeout = 5;
static unsigned long dnsFailureTimeout = 300u;

static struct {
   const char *name;
   dnsType_t   type;
} dnsTypes[] = {
   { "ANY",   DNS_TYPE_ANY },
   { "A",     DNS_TYPE_A },
   { "AAAA",  DNS_TYPE_AAAA },
   { "TXT",   DNS_TYPE_TXT },
   { "NS",    DNS_TYPE_NS },
   { "CNAME", DNS_TYPE_CNAME },
   { "SOA",   DNS_TYPE_SOA },
   { "PTR",   DNS_TYPE_PTR },
   { "NAPTR", DNS_TYPE_NAPTR },
   { "MX",    DNS_TYPE_MX },
   { "OPT",   DNS_TYPE_OPT },
   { NULL,    0 }
};

void dnsInit(const char *name, ...)
{
    va_list ap;

    Ns_MutexLock(&dnsMutex);
    va_start(ap, name);

    if (!strcmp(name, "nameserver")) {
        char *s, *n;
        dnsServer *server, *next;
        while ((s = va_arg(ap, char *))) {
            while (s) {
                if ((n = strchr(s, ','))) {
                    *n++ = 0;
                }
                server = ns_calloc(1, sizeof(dnsServer));
                server->name = ns_strdup(s);
                //Ns_GetSockAddr((struct sockaddr *)&(server->sa), server->name, 0);
                //server->ipaddr = inet_addr(s);
                for (next = dnsServers; next && next->next; next = next->next) {
                    ;
                }
                if (next == 0) {
                    dnsServers = server;
                } else {
                    next->next = server;
                }
                s = n;
            }
        }
    } else
     if (!strcmp(name, "debug")) {
        dnsDebug = va_arg(ap, int);
    } else
     if (!strcmp(name, "port")) {
        dnsResolverPort = (unsigned short)va_arg(ap, int);
    } else
    if (!strcmp(name, "retry")) {
        dnsResolverRetries = va_arg(ap, int);
    } else
     if (!strcmp(name, "timeout")) {
        dnsResolverTimeout = va_arg(ap, int);
    } else
     if (!strcmp(name, "failuretimeout")) {
        dnsFailureTimeout = va_arg(ap, unsigned long);
    } else
     if (!strcmp(name, "ttl")) {
        dnsTTL = va_arg(ap, unsigned long);
    }
    va_end(ap);
    Ns_MutexUnlock(&dnsMutex);
}

/* DNS over TCP uses a two-byte length prefix and permits partial I/O. */
static bool dnsTcpTransfer(NS_SOCKET sock, char *data, size_t length,
                           const Ns_Time *timeout, bool writeData)
{
    while (length > 0) {
        ssize_t count = writeData ? Ns_SockSend(sock, data, length, timeout)
                                 : Ns_SockRecv(sock, data, length, timeout);
        if (count <= 0) return NS_FALSE;
        data += count;
        length -= (size_t)count;
    }
    return NS_TRUE;
}

dnsPacket *dnsResolveTcp(dnsPacket *req, const char *server,
                         unsigned short port, int timeout)
{
    Ns_Time wait = {timeout > 0 ? timeout : 5, 0};
    NS_SOCKET sock = Ns_SockTimedConnect(server, port, &wait);
    uint16_t length;
    char *data = NULL;
    dnsPacket *reply = NULL;

    if (sock == NS_INVALID_SOCKET) return NULL;
    Ns_SockSetNonBlocking(sock);
    if (!dnsTcpTransfer(sock, req->buf.data, (size_t)req->buf.size + 2, &wait, NS_TRUE)
        || !dnsTcpTransfer(sock, (char *)&length, sizeof(length), &wait, NS_FALSE)) goto done;
    length = ntohs(length);
    if (length < DNS_HEADER_LEN) goto done;
    data = ns_malloc(length);
    if (!dnsTcpTransfer(sock, data, length, &wait, NS_FALSE)) goto done;
    reply = dnsParsePacket((unsigned char *)data, length);
    if (reply != NULL && (reply->id != req->id || !DNS_GET_QR(reply->u)
        || DNS_GET_TC(reply->u) || reply->qdcount != 1
        || reply->qdlist->type != req->qdlist->type
        || strcasecmp(reply->qdlist->name, req->qdlist->name) != 0)) {
        dnsPacketFree(reply, 0);
        reply = NULL;
    }
done:
    ns_free(data);
    ns_sockclose(sock);
    return reply;
}

dnsPacket *dnsLookup(char *name, dnsType_t type, int *errcode)
{
    char buf[DNS_BUFSIZE];
    dnsServer *server = 0;
    dnsPacket *req, *reply;
    int sock = NS_INVALID_SOCKET;

    req = dnsPacketCreateQuery(name, type);
    dnsEncodePacket(req);

    while (1) {
        int                        timeout, retries, rc;
        time_t                     now;
        struct NS_SOCKADDR_STORAGE sa;
        struct sockaddr           *saPtr = (struct sockaddr *)&sa;

        now = time(0);
        Ns_MutexLock(&dnsMutex);
        retries = dnsResolverRetries;
        timeout = dnsResolverTimeout;
        if (server != 0) {
            /* Disable only if we have more than one server */
            if (++server->fail_count > 2 && dnsServers->next) {
                server->fail_time = (unsigned long)now;
                Ns_Log(Notice, "dnsLookup: %s: nameserver disabled", server->name);
            }
            server = server->next;
        } else {
            server = dnsServers;
        }
        while (server) {
            if (server->fail_time > 0u
                && (unsigned long)now - server->fail_time > dnsFailureTimeout
                ) {
                server->fail_count = server->fail_time = 0;
                Ns_Log(Notice, "dnsLookup: %s: nameserver re-enabled", server->name);
            }
            if (server->fail_time == 0) {
                break;
            }
            server = server->next;
        }
        Ns_MutexUnlock(&dnsMutex);
        if (server == 0) {
            break;
        }
        if (dnsDebug > 5) {
            Ns_Log(Notice, "dnsLookup: %s: resolving %s...", server->name, name);
        }

        rc = Ns_GetSockAddr(saPtr, server->name, dnsResolverPort);
        if (rc != TCL_OK) {
            Ns_Log(Error, "dnsLookup: invalid server name '%s'", server->name);
            continue;
        }

        if (sock != NS_INVALID_SOCKET) {
            ns_close(sock);
            sock = NS_INVALID_SOCKET;
        }
        if (sock == NS_INVALID_SOCKET) {
            if ((sock = socket(saPtr->sa_family, SOCK_DGRAM, 0)) < 0) {
                if (errcode != 0) {
                    *errcode = errno;
                }
                continue;
            }
        }
        if (connect(sock, saPtr, Ns_SockaddrGetSockLen(saPtr)) != 0) {
            continue;
        }
        while (retries--) {
            ssize_t len;

            if (send(sock, req->buf.data + 2, req->buf.size, 0) < 0) {
                if (dnsDebug > 3) {
                    Ns_Log(Error, "dnsLookup: %s: sendto: %s", server->name, strerror(errno));
                }
                continue;
            }
            if (Ns_SockWait(sock, NS_SOCK_READ, timeout) != NS_OK) {
                if (dnsDebug > 3 && errno) {
                    Ns_Log(Error, "dnsLookup: %s: select: %s", server->name, strerror(errno));
                }
                continue;
            }
            if ((len = recv(sock, buf, DNS_BUFSIZE, 0)) <= 0) {
                if (dnsDebug > 3) {
                    Ns_Log(Error, "dnsLookup: %s: recvfrom: %s", server->name, strerror(errno));
                }
                continue;
            }
            if (!(reply = dnsParsePacket((unsigned char*)buf, (size_t)len))) {
                continue;
            }
            /* DNS packet id should be the same */
            if (reply->id == req->id && DNS_GET_QR(reply->u)
                && reply->qdcount == 1 && reply->qdlist->type == req->qdlist->type
                && strcasecmp(reply->qdlist->name, req->qdlist->name) == 0) {
                if (DNS_GET_TC(reply->u)) {
                    dnsPacketFree(reply, 0);
                    reply = dnsResolveTcp(req, server->name, dnsResolverPort, timeout);
                    if (reply == NULL) continue;
                }
                ns_close(sock);
                dnsPacketFree(req, 0);
                Ns_MutexLock(&dnsMutex);
                server->fail_count = server->fail_time = 0;
                Ns_MutexUnlock(&dnsMutex);
                return reply;
            }
            dnsPacketFree(reply, 0);
        }
    }
    dnsPacketFree(req, 0);
    ns_close(sock);
    if (errcode != 0) {
        *errcode = ENOENT;
    }
    return 0;
}

dnsPacket *dnsResolve(char *name, dnsType_t type, const char *server, int timeout, int retries)
{
    return dnsResolveAt(name, type, server, 53, timeout, retries);
}

dnsPacket *dnsResolveAt(char *name, dnsType_t type, const char *server,
                        unsigned short port, int timeout, int retries)
{
    int sock;
    char buf[DNS_BUFSIZE];
    dnsPacket *req, *reply;
    struct NS_SOCKADDR_STORAGE sa;
    struct sockaddr *saPtr = (struct sockaddr *)&sa;

    if (retries <= 0) {
        retries = 3;
    }
    if (timeout <= 0) {
        timeout = 5;
    }
    if (Ns_GetSockAddr(saPtr, server, port) != NS_OK) {
        return NULL;
    }
    if ((sock = socket(saPtr->sa_family, SOCK_DGRAM, 0)) < 0) {
        if (dnsDebug > 3) {
            Ns_Log(Error, "dnsResolve: %s: socket: %s", name, strerror(errno));
        }
        return 0;
    }
    if (connect(sock, saPtr, Ns_SockaddrGetSockLen(saPtr)) != 0) {
        ns_close(sock);
        return NULL;
    }
    req = dnsPacketCreateQuery(name, type);
    dnsEncodePacket(req);
    while (retries--) {
        ssize_t len;

        if (send(sock, req->buf.data + 2, req->buf.size, 0) < 0) {
            if (dnsDebug > 3) {
                Ns_Log(Error, "dnsResolve: %s: sendto: %s", name, strerror(errno));
            }
            continue;
        }
        if (dnsDebug > 3) {
            Ns_Log(Notice, "dnsResolve: %s: %d: sending to %s, timeout=%d", name, req->id, server, timeout);
        }
        if (Ns_SockWait(sock, NS_SOCK_READ, timeout) != NS_OK) {
            if (dnsDebug > 3 && errno) {
                Ns_Log(Error, "dnsResolve: %s: select: %s", name, strerror(errno));
            }
            continue;
        }
        if ((len = recv(sock, buf, DNS_BUFSIZE, 0)) <= 0) {
            if (dnsDebug > 3) {
                Ns_Log(Error, "dnsResolve: %s: recvfrom: %s", name, strerror(errno));
            }
            continue;
        }
        if (dnsDebug > 3) {
            Ns_Log(Notice, "dnsResolve: %s: received %ld bytes from server %s", name, len, server);
        }
        if (!(reply = dnsParsePacket((unsigned char*)buf, (size_t)len))) {
            continue;
        }
        /* DNS packet id should be the same */
        if (reply->id == req->id && DNS_GET_QR(reply->u)
                && reply->qdcount == 1 && reply->qdlist->type == req->qdlist->type
                && strcasecmp(reply->qdlist->name, req->qdlist->name) == 0) {
            if (DNS_GET_TC(reply->u)) {
                dnsPacketFree(reply, 0);
                reply = dnsResolveTcp(req, server, port, timeout);
                if (reply == NULL) continue;
            }
            dnsPacketFree(req, 0);
            ns_close(sock);
            return reply;
        }
        if (dnsDebug > 3) {
            Ns_Log(Notice, "dnsResolve: %s: %d: wrong ID %d from to %s", name, req->id, reply->id, server);
        }
        dnsPacketFree(reply, 0);
    }
    dnsPacketFree(req, 0);
    ns_close(sock);
    return 0;
}

void dnsRecordDump(Tcl_DString *ds, dnsRecord *y)
{
    char ipString[NS_IPADDR_SIZE];

    if (y != NULL) {
        Ns_DStringPrintf(ds, "Name=%s, Type=%s(%d), Class=%u, TTL=%lu, Length=%u, ",
                         y->name, dnsTypeStr(y->type), y->type, y->class, y->ttl, y->len);
        switch (y->type) {
        case DNS_TYPE_A: /* fall through */
        case DNS_TYPE_AAAA:
            Ns_DStringPrintf(ds, "IP=%s ", ns_inet_ntop( (struct sockaddr *)&(y->data.sa), ipString, NS_IPADDR_SIZE));
            break;

        case DNS_TYPE_MX:
            if (y->data.mx == 0) {
                break;
            }
            Ns_DStringPrintf(ds, "MX=%u, %s ", y->data.mx->preference, y->data.mx->name);
            break;
        case DNS_TYPE_NS:
            Ns_DStringPrintf(ds, "NS=%s ", y->data.name);
            break;
        case DNS_TYPE_CNAME:
            Ns_DStringPrintf(ds, "CNAME=%s ", y->data.name);
            break;
        case DNS_TYPE_PTR:
            Ns_DStringPrintf(ds, "PTR=%s ", y->data.name);
            break;
        case DNS_TYPE_SOA:
            if (y->data.soa == 0) {
                break;
            }
            Ns_DStringPrintf(ds, "MNAME=%s, RNAME=%s, SERIAL=%lu, REFRESH=%lu, RETRY=%lu, EXPIRE=%lu, TTL=%lu ",
                             y->data.soa->mname, y->data.soa->rname, y->data.soa->serial,
                             y->data.soa->refresh, y->data.soa->retry, y->data.soa->expire, y->data.soa->ttl);
            break;
        case DNS_TYPE_NAPTR:
            if (y->data.naptr == 0) {
                break;
            }
            Ns_DStringPrintf(ds, "ORDER=%d, PREFS=%d, FLAGS=%s, SERVICE=%s, REGEXP=%s, REPLACE=%s, TTL=%lu ",
                             y->data.naptr->order, y->data.naptr->preference, y->data.naptr->flags, y->data.naptr->service,
                             y->data.naptr->regexp, y->data.naptr->replace, y->data.soa->ttl);
            break;
        case DNS_TYPE_WKS:
            Ns_DStringPrintf(ds, "WKS");
            break;
        case DNS_TYPE_HINFO:
            Ns_DStringPrintf(ds, "HINFO");
            break;
        case DNS_TYPE_MINFO:
            Ns_DStringPrintf(ds, "MINFO");
            break;
        case DNS_TYPE_TXT:
            Ns_DStringPrintf(ds, "TXT");
            break;
        case DNS_TYPE_SRV:
            Ns_DStringPrintf(ds, "SRV");
            break;
        case DNS_TYPE_OPT:
            Ns_DStringPrintf(ds, "OPT");
            break;
        case DNS_TYPE_ANY:
            Ns_DStringPrintf(ds, "ANY");
            break;
        }
        if (y->timestamp != 0) {
            Ns_DStringPrintf(ds, ", TIMESTAMP=%lu", y->timestamp);
        }
    }
}

void dnsRecordLog(dnsRecord *rec, int level, const char *text, ...)
{
    Tcl_DString ds;
    va_list ap;

    if (level > dnsDebug) {
        return;
    }
    va_start(ap, text);

    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, "nsdns: ", TCL_INDEX_NONE);
    Ns_DStringVPrintf(&ds, text, ap);
    dnsRecordDump(&ds, rec);
    Ns_Log(level < 0 ? Error : Notice, "%s", ds.string);
    Tcl_DStringFree(&ds);
    va_end(ap);
}

void dnsRecordFree(dnsRecord *pkt)
{
    if (pkt == 0) {
        return;
    }
    ns_free(pkt->name);
    switch (pkt->type) {
    case DNS_TYPE_TXT:
        ns_free(pkt->data.txt);
        break;
    case DNS_TYPE_MX:
        if (pkt->data.mx == 0) {
            break;
        }
        ns_free(pkt->data.mx->name);
        ns_free(pkt->data.mx);
        break;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        ns_free(pkt->data.name);
        break;
    case DNS_TYPE_NAPTR:
        if (pkt->data.naptr == 0) {
            break;
        }
        ns_free(pkt->data.naptr->flags);
        ns_free(pkt->data.naptr->service);
        ns_free(pkt->data.naptr->regexp);
        ns_free(pkt->data.naptr->replace);
        ns_free(pkt->data.naptr);
        break;
    case DNS_TYPE_SOA:
        if (pkt->data.soa == 0) {
            break;
        }
        ns_free(pkt->data.soa->mname);
        ns_free(pkt->data.soa->rname);
        ns_free(pkt->data.soa);
        break;
    case DNS_TYPE_A: /* fall through */
    case DNS_TYPE_AAAA: /* fall through */
    case DNS_TYPE_ANY: /* fall through */
    case DNS_TYPE_HINFO: /* fall through */
    case DNS_TYPE_MINFO: /* fall through */
    case DNS_TYPE_OPT: /* fall through */
    case DNS_TYPE_SRV: /* fall through */
    case DNS_TYPE_WKS: /* fall through */
        /*
         * TODO: double check, if not any of these records require freeing
         */
        break;
    }
    ns_free(pkt);
}

void dnsRecordDestroy(dnsRecord **pkt)
{
    if (pkt == 0) {
        return;
    }
    while (*pkt) {
        dnsRecord *next = (*pkt)->next;
        dnsRecordFree(*pkt);
        *pkt = next;
    }
}

dnsRecord *dnsRecordCreate(dnsRecord *from)
{
    dnsRecord *rec = ns_calloc(1, sizeof(dnsRecord));
    if (from != 0) {
        rec->name = ns_strcopy(from->name);
        rec->nsize = from->nsize;
        rec->type = from->type;
        rec->class = from->class;
        rec->ttl = from->ttl;
        rec->len = from->len;
        switch (rec->type) {
        case DNS_TYPE_TXT:
            if (from->len != 0 && from->data.txt != NULL) {
                rec->data.txt = ns_malloc(from->len);
                memcpy(rec->data.txt, from->data.txt, from->len);
            }
            break;
        case DNS_TYPE_A: /* fall through */
        case DNS_TYPE_AAAA:
            rec->data.sa = from->data.sa;
            break;
        case DNS_TYPE_MX:
            rec->data.mx = ns_calloc(1, sizeof(dnsMX));
            if (from->data.mx == 0) {
                break;
            }
            rec->data.mx->name = ns_strcopy(from->data.mx->name);
            rec->data.mx->preference = from->data.mx->preference;
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
            rec->data.name = ns_strcopy(from->data.name);
            break;
        case DNS_TYPE_NAPTR:
            rec->data.naptr = ns_calloc(1, sizeof(dnsNAPTR));
            if (from->data.naptr == 0) {
                break;
            }
            rec->data.naptr->order = from->data.naptr->order;
            rec->data.naptr->preference = from->data.naptr->preference;
            rec->data.naptr->flags = ns_strcopy(from->data.naptr->flags);
            rec->data.naptr->service = ns_strcopy(from->data.naptr->service);
            rec->data.naptr->regexp = ns_strcopy(from->data.naptr->regexp);
            rec->data.naptr->replace = ns_strcopy(from->data.naptr->replace);
            break;
        case DNS_TYPE_SOA:
            rec->data.soa = ns_calloc(1, sizeof(dnsSOA));
            if (from->data.soa == 0) {
                break;
            }
            rec->data.soa->mname = ns_strcopy(from->data.soa->mname);
            rec->data.soa->rname = ns_strcopy(from->data.soa->rname);
            rec->data.soa->serial = from->data.soa->serial;
            rec->data.soa->refresh = from->data.soa->refresh;
            rec->data.soa->retry = from->data.soa->retry;
            rec->data.soa->expire = from->data.soa->expire;
            rec->data.soa->ttl = from->data.soa->ttl;
            break;
        case DNS_TYPE_WKS: /* fall through */
        case DNS_TYPE_HINFO: /* fall through */
        case DNS_TYPE_MINFO: /* fall through */
        case DNS_TYPE_SRV: /* fall through */
        case DNS_TYPE_OPT: /* fall through */
        case DNS_TYPE_ANY: /* fall through */
            /*
             * TODO: check, if any of these types should do something here
             */
            break;
        }
        dnsRecordUpdate(rec);
    }
    return rec;
}

dnsRecord *dnsRecordCreateAAAA(const char *name, const char *ipAddr)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));

    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_AAAA;
    y->class = DNS_CLASS_INET;
    y->len = 16;
    ((struct sockaddr *)&y->data.sa)->sa_family = AF_INET6;
    if (ipAddr != NULL && inet_pton(AF_INET6, ipAddr,
            &((struct sockaddr_in6 *)&y->data.sa)->sin6_addr) != 1) {
        dnsRecordFree(y);
        return NULL;
    }
    y->ttl = dnsTTL;
    return y;
}

dnsRecord *dnsRecordCreateA(const char *name, const char *ipAddr)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));

    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_A;
    y->class = DNS_CLASS_INET;
    y->len = 4;
    ((struct sockaddr *)&y->data.sa)->sa_family = AF_INET;
    if (ipAddr != NULL && inet_pton(AF_INET, ipAddr,
            &((struct sockaddr_in *)&y->data.sa)->sin_addr) != 1) {
        dnsRecordFree(y);
        return NULL;
    }
    y->ttl = dnsTTL;
    return y;
}

/* A TXT value is a Tcl list of byte strings. Preserve string boundaries. */
dnsRecord *dnsRecordCreateTXT(Tcl_Interp *interp, const char *name, Tcl_Obj *strings)
{
    Tcl_Obj **values;
    int count, i;
    size_t size = 0, offset = 0;
    dnsRecord *rec;

    if (Tcl_ListObjGetElements(interp, strings, &count, &values) != TCL_OK) {
        return NULL;
    }
    if (count == 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("TXT requires at least one string", -1));
        return NULL;
    }
    for (i = 0; i < count; i++) {
        int length;
        (void)Tcl_GetByteArrayFromObj(values[i], &length);
        if (length > 255 || size + (size_t)length + 1 > 65535) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("TXT strings must be at most 255 bytes; RDATA at most 65535 bytes", -1));
            return NULL;
        }
        size += (size_t)length + 1;
    }
    rec = dnsRecordCreate(NULL);
    rec->name = ns_strdup(name);
    rec->nsize = (short)strlen(name);
    rec->type = DNS_TYPE_TXT;
    rec->class = DNS_CLASS_INET;
    rec->ttl = dnsTTL;
    rec->len = (unsigned short)size;
    rec->data.txt = ns_malloc(size);
    for (i = 0; i < count; i++) {
        int length;
        unsigned char *bytes = Tcl_GetByteArrayFromObj(values[i], &length);
        rec->data.txt[offset++] = (unsigned char)length;
        memcpy(rec->data.txt + offset, bytes, (size_t)length);
        offset += (size_t)length;
    }
    return rec;
}

dnsRecord *dnsRecordCreateNS(char *name, char *data)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));
    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_NS;
    y->class = DNS_CLASS_INET;
    y->data.name = ns_strcopy(data);
    if (y->data.name != 0) {
        y->len = (unsigned short)strlen(y->data.name);
    }
    y->ttl = dnsTTL;
    return y;
}

dnsRecord *dnsRecordCreateCNAME(char *name, char *data)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));
    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_CNAME;
    y->class = DNS_CLASS_INET;
    y->data.name = ns_strcopy(data);
    if (y->data.name != 0) {
        y->len = (unsigned short)strlen(y->data.name);
    }
    y->ttl = dnsTTL;
    return y;
}

dnsRecord *dnsRecordCreatePTR(char *name, char *data)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));
    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1);
    strcpy(y->name, name);
    y->type = DNS_TYPE_PTR;
    y->class = DNS_CLASS_INET;
    y->data.name = ns_strcopy(data);
    if (y->data.name != 0) {
        y->len = (unsigned short)strlen(y->data.name);
    }
    y->ttl = dnsTTL;
    return y;
}

dnsRecord *dnsRecordCreateMX(char *name, unsigned short preference, char *data)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));
    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_MX;
    y->class = DNS_CLASS_INET;
    y->data.mx = ns_calloc(1, sizeof(dnsMX));
    y->data.mx->preference = preference;
    y->data.mx->name = ns_strcopy(data);
    y->len = 2;
    if (y->data.name != 0) {
        y->len += strlen(y->data.name);
    }
    y->ttl = dnsTTL;
    return y;
}

dnsRecord *dnsRecordCreateNAPTR(char *name, short order, short preference, char *flags, char *service, char *regexp,
                                char *replace)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));
    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_NAPTR;
    y->class = DNS_CLASS_INET;
    y->data.naptr = ns_calloc(1, sizeof(dnsNAPTR));
    y->data.naptr->order = order;
    y->data.naptr->preference = preference;
    y->data.naptr->flags = ns_strcopy(flags);
    y->data.naptr->service = ns_strcopy(service);
    y->data.naptr->regexp = ns_strcopy(regexp && *regexp ? regexp : 0);
    y->data.naptr->replace = ns_strcopy(replace && *replace ? replace : 0);
    y->len = 2;
    if (y->data.name != 0) {
        y->len += strlen(y->data.name);
    }
    y->ttl = dnsTTL;
    return y;
}

dnsRecord *dnsRecordCreateSOA(char *name, char *mname, char *rname,
                              unsigned long serial, unsigned long refresh,
                              unsigned long retry, unsigned long expire, unsigned long ttl)
{
    dnsRecord *y = ns_calloc(1, sizeof(dnsRecord));
    y->nsize = (short)strlen(name);
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);
    y->type = DNS_TYPE_SOA;
    y->class = DNS_CLASS_INET;
    y->data.soa = ns_calloc(1, sizeof(dnsSOA));
    y->data.soa->mname = ns_strcopy(mname);
    y->data.soa->rname = ns_strcopy(rname);
    y->data.soa->serial = serial;
    y->data.soa->refresh = refresh;
    y->data.soa->retry = retry;
    y->data.soa->expire = expire;
    y->data.soa->ttl = (ttl != 0) ? ttl : dnsTTL;
    y->len = 20;
    if (y->data.soa->mname != 0) {
        y->len += strlen(y->data.soa->mname);

    }
    if (y->data.soa->rname != 0) {
        y->len += strlen(y->data.soa->rname);
    }
    y->ttl = dnsTTL;
    return y;
}

Tcl_Obj *dnsRecordCreateTclObj(Tcl_Interp *interp, dnsRecord *drec)
{
    Tcl_Obj *list = Tcl_NewListObj(0, 0);

    while (drec) {
        char             ipString[NS_IPADDR_SIZE];
        struct sockaddr *saPtr;
        Tcl_Obj          *obj = Tcl_NewListObj(0, 0);

        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->name, -1));
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char *) dnsTypeStr(drec->type), -1));
        switch (drec->type) {
        case DNS_TYPE_TXT: {
            Tcl_Obj *strings = Tcl_NewListObj(0, NULL);
            size_t offset = 0;
            while (offset < drec->len && drec->data.txt != NULL) {
                int length = drec->data.txt[offset++];
                Tcl_ListObjAppendElement(interp, strings,
                    Tcl_NewByteArrayObj(drec->data.txt + offset, length));
                offset += (size_t)length;
            }
            Tcl_ListObjAppendElement(interp, obj, strings);
            break;
        }
        case DNS_TYPE_A: /* fall through */
        case DNS_TYPE_AAAA:
            saPtr = (struct sockaddr *)&(drec->data.sa);
            Tcl_ListObjAppendElement(interp, obj,
                                     Tcl_NewStringObj(ns_inet_ntop(saPtr, ipString, sizeof(ipString)), -1));
            break;
        case DNS_TYPE_MX:
            if (drec->data.mx == 0) {
                break;
            }
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.mx->name, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(drec->data.mx->preference));
            break;
        case DNS_TYPE_NAPTR:
            if (drec->data.naptr == 0) {
                break;
            }
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(drec->data.naptr->order));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(drec->data.naptr->preference));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.naptr->flags, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.naptr->service, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.naptr->regexp, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.naptr->replace, -1));
            break;
        case DNS_TYPE_SOA:
            if (drec->data.soa == 0) {
                break;
            }
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.soa->mname, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.soa->rname, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewWideIntObj((Tcl_WideInt)drec->data.soa->serial));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewWideIntObj((Tcl_WideInt)drec->data.soa->refresh));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewWideIntObj((Tcl_WideInt)drec->data.soa->retry));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewWideIntObj((Tcl_WideInt)drec->data.soa->expire));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewWideIntObj((Tcl_WideInt)drec->data.soa->ttl));
            break;
        case DNS_TYPE_ANY:   /* fall through */
        case DNS_TYPE_CNAME: /* fall through */
        case DNS_TYPE_HINFO: /* fall through */
        case DNS_TYPE_MINFO: /* fall through */
        case DNS_TYPE_NS:    /* fall through */
        case DNS_TYPE_OPT:   /* fall through */
        case DNS_TYPE_PTR:   /* fall through */
        case DNS_TYPE_SRV:   /* fall through */
        case DNS_TYPE_WKS:   /* fall through */
        default:
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(drec->data.name, -1));
        }
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewWideIntObj((Tcl_WideInt)drec->ttl));
        Tcl_ListObjAppendElement(interp, list, obj);
        drec = drec->next;
    }
    return list;
}

void dnsRecordUpdate(dnsRecord *rec)
{
    if (rec->type == DNS_TYPE_NAPTR) {
        /*
         * Save pointer in the regexp where phone number should be
         * placed for quick replace later
         */
        if ((dnsFlags & DNS_NAPTR_REGEXP && rec->data.naptr->regexp)) {
            if ((rec->data.naptr->regexp_p2 = strchr(rec->data.naptr->regexp, '@'))) {
                for (rec->data.naptr->regexp_p1 = rec->data.naptr->regexp_p2;
                     rec->data.naptr->regexp_p1 > rec->data.naptr->regexp
                         && *rec->data.naptr->regexp_p1 != ':';
                     rec->data.naptr->regexp_p1--) {
                    ;
                }
            }
        }
    }
}

dnsRecord *dnsRecordAppend(dnsRecord **list, dnsRecord *pkt)
{
    if (!list || !pkt) {
        return 0;
    }
    for (; *list; list = &(*list)->next) {
        pkt->prev = *list;
    }
    *list = pkt;
    return *list;
}

dnsRecord *dnsRecordInsert(dnsRecord **list, dnsRecord *pkt)
{
    if (!list || !pkt) {
        return 0;
    }
    pkt->next = *list;
    if (*list != NULL) (*list)->prev = pkt;
    *list = pkt;
    return *list;
}

dnsRecord *dnsRecordRemove(dnsRecord **list, dnsRecord *link)
{
    if (!list || !link) {
        return 0;
    }
    for (; *list; list = &(*list)->next) {
        if (*list != link) {
            continue;
        }
        if (link->next != 0) {
            link->next->prev = link->prev;
        }
        if (link->prev != 0) {
            link->prev->next = link->next;
        }
        *list = link->next;
        link->next = link->prev = 0;
        return link;
    }
    return 0;
}

int dnsRecordSearch(dnsRecord *list, dnsRecord *rec, int replace)
{
    dnsRecord *drec;

    for (drec = list; drec; drec = drec->next) {
        if (drec->type != rec->type || strcasecmp(drec->name, rec->name) != 0) {
            continue;
        }
        switch (drec->type) {
        case DNS_TYPE_TXT:
            if (rec->len == drec->len && (rec->len == 0
                || (rec->data.txt != NULL && drec->data.txt != NULL
                    && memcmp(rec->data.txt, drec->data.txt, rec->len) == 0))) {
                if (replace != 0) {
                    drec->ttl = rec->ttl;
                    drec->timestamp = rec->timestamp;
                }
                return 1;
            }
            break;
        case DNS_TYPE_A: /* fall through */
        case DNS_TYPE_AAAA:
            if (Ns_SockaddrSameIP((struct sockaddr *)&(rec->data.sa),
                                  (struct sockaddr *)&(drec->data.sa)) == NS_TRUE) {
                if (replace != 0) {
                    rec->ttl = drec->ttl;
                }
                return 1;
            }
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
            if (!rec->data.name || !drec->data.name) {
                return -1;
            }
            if (!strcmp(rec->data.name, drec->data.name)) {
                if (replace != 0) {
                    rec->ttl = drec->ttl;
                }
                return 1;
            }
            break;
        case DNS_TYPE_MX:
            if (!rec->data.mx || !rec->data.mx->name || !drec->data.mx || !drec->data.mx->name) {
                return -1;
            }
            if (!strcmp(rec->data.mx->name, drec->data.mx->name)) {
                if (replace != 0) {
                    rec->ttl = drec->ttl;
                    rec->data.mx->preference = drec->data.mx->preference;
                }
                return 1;
            }
            break;
        case DNS_TYPE_NAPTR:
            if (!rec->data.naptr || !drec->data.naptr ||
                (!rec->data.naptr->regexp && !rec->data.naptr->replace) ||
                (!drec->data.naptr->regexp && !drec->data.naptr->replace)) {
                return -1;
            }
            if ((rec->data.naptr->regexp && drec->data.naptr->regexp &&
                 !strcmp(rec->data.naptr->regexp, drec->data.naptr->regexp)) ||
                (rec->data.naptr->replace && drec->data.naptr->replace &&
                 !strcmp(rec->data.naptr->replace, drec->data.naptr->replace))) {
                if (replace != 0) {
                    rec->ttl = drec->ttl;
                    rec->data.mx->preference = drec->data.mx->preference;
                }
                return 1;
            }
            break;
        case DNS_TYPE_SOA:
            if (!rec->data.soa || !drec->data.soa) {
                return -1;
            }
            /* Only one SOA record per domain */
            if (replace != 0) {
                rec->ttl = drec->ttl;
                if (rec->data.soa->serial != drec->data.soa->serial) {
                    ns_free(rec->data.soa->mname);
                    rec->data.soa->mname = ns_strcopy(drec->data.soa->mname);
                    ns_free(rec->data.soa->rname);
                    rec->data.soa->rname = ns_strcopy(drec->data.soa->rname);
                    rec->data.soa->serial = drec->data.soa->serial;
                    rec->data.soa->refresh = drec->data.soa->refresh;
                    rec->data.soa->retry = drec->data.soa->retry;
                    rec->data.soa->expire = drec->data.soa->expire;
                    rec->data.soa->ttl = drec->data.soa->ttl;
                }
            }
            return 1;
            break;
        case DNS_TYPE_ANY:   /* fall through */
        case DNS_TYPE_HINFO: /* fall through */
        case DNS_TYPE_MINFO: /* fall through */
        case DNS_TYPE_OPT:   /* fall through */
        case DNS_TYPE_SRV:   /* fall through */
        case DNS_TYPE_WKS:   /* fall through */
        default:
            return -1;
        }
    }
    return 0;
}

int dnsParseString(dnsPacket *pkt, char **buf)
{
    size_t len;
    char *end = pkt->buf.data + 2 + pkt->buf.size;
    if (pkt->buf.ptr >= end) {
        return -1;
    }
    len = (unsigned char)*pkt->buf.ptr++;
    if ((size_t)(end - pkt->buf.ptr) < len) {
        return -1;
    }
    *buf = ns_malloc(len + 1);
    memcpy(*buf, pkt->buf.ptr, len);
    (*buf)[len] = '\0';
    pkt->buf.ptr += len;
    return 0;
}

short dnsParseName(dnsPacket *pkt, char **ptr, char *buf, int buflen, short pos, int level)
{
    char *end = pkt->buf.data + 2 + pkt->buf.size;
    if (level > 15) {
        return -1;
    }
    while (*ptr < end) {
        unsigned int len = (unsigned char)*(*ptr)++;
        if (len == 0) {
            if (pos > 0 && buf[pos - 1] == '.') {
                pos--;
            }
            buf[pos] = '\0';
            return pos;
        }
        if ((len & 0xc0u) == 0xc0u) {
            unsigned int offset;
            char *p;
            if (*ptr >= end) return -1;
            offset = ((len & 0x3fu) << 8) | (unsigned char)*(*ptr)++;
            if (offset >= pkt->buf.size) return -1;
            p = pkt->buf.data + 2 + offset;
            return dnsParseName(pkt, &p, buf, buflen, pos, level + 1);
        }
        if (len > 63 || (size_t)(end - *ptr) < len
            || (unsigned int)pos + len + 1 >= (unsigned int)buflen) {
            return -1;
        }
        memcpy(buf + pos, *ptr, len);
        pos += (short)len;
        *ptr += len;
        buf[pos++] = '.';
    }
    return -1;
}

dnsPacket *dnsParseHeader(void *buf, size_t size)
{
    unsigned short p[6];
    dnsPacket *pkt;

    if (size < DNS_HEADER_LEN || size > 65535) {
        return NULL;
    }

    pkt = ns_calloc(1, sizeof(dnsPacket));
    memcpy(p, buf, sizeof(p));
    pkt->id = ntohs(p[0]);
    pkt->u = ntohs(p[1]);
    pkt->qdcount = ntohs(p[2]);
    pkt->ancount = ntohs(p[3]);
    pkt->nscount = ntohs(p[4]);
    pkt->arcount = ntohs(p[5]);
    /* First two bytes are reserved for packet length
       in TCP mode plus some overhead in case we compress worse
       than it was */
    pkt->buf.allocated = size + 128;
    pkt->buf.data = ns_malloc(pkt->buf.allocated);
    /* Ns_Log(Debug,"parse[%d]: %x %x, %d",getpid(),pkt,pkt->buf.data,pkt->buf.allocated); */
    pkt->buf.size = (unsigned short)size;
    memcpy(pkt->buf.data + 2, buf, (unsigned) size);
    pkt->buf.ptr = &pkt->buf.data[DNS_HEADER_LEN + 2];
    return pkt;
}

dnsRecord *dnsParseRecord(dnsPacket *pkt, int query)
{
    /* int offset; */
    uint32_t ul;
    char *rdataEnd = NULL;
    unsigned short us;
    char name[256] = {'\0'};
    dnsRecord *y;

    y = ns_calloc(1, sizeof(dnsRecord));
    /* offset = (pkt->buf.ptr - pkt->buf.data) - 2; */

    /*
     * Get the name of the resource
     */
    y->nsize = dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0);
    /* fprintf(stderr, "=== dnsParseRecord name %s, len %d\n", name, y->nsize); */
    if (y->nsize < 0) {
        snprintf(name, 255, "invalid name: %d", y->nsize);
        goto err;
    }
    y->name = ns_malloc((size_t)y->nsize + 1u);
    strcpy(y->name, name);

    /*
     * Get the type of data
     */
    if (pkt->buf.ptr + 2 > pkt->buf.data + 2 + pkt->buf.size) {
        strcpy(name, "invalid type position");
        goto err;
    }
    memcpy(&us, pkt->buf.ptr, sizeof(us));
    y->type = ntohs(us);
    pkt->buf.ptr += 2;
    /*
     * Get the class type
     */
    if (pkt->buf.ptr + 2 > pkt->buf.data + 2 + pkt->buf.size) {
        strcpy(name, "invalid class position");
        goto err;
    }
    memcpy(&us, pkt->buf.ptr, sizeof(us));
    y->class = ntohs(us);
    pkt->buf.ptr += 2;
    /* Query block stops here */
    if (query != 0)
        goto rec;
    /*
     * Answer blocks carry a TTL and the actual data.
     */
    if (pkt->buf.ptr + 4 > pkt->buf.data + 2 + pkt->buf.size) {
        strcpy(name, "invalid TTL position");
        goto err;
    }
    memcpy(&ul, pkt->buf.ptr, sizeof(ul));
    y->ttl = ntohl(ul);

    pkt->buf.ptr += 4;
    /*
     * Fetch the resource data.
     */
    if (pkt->buf.ptr + 2 > pkt->buf.data + 2 + pkt->buf.size) {
        strcpy(name, "invalid data position");
        goto err;
    }
    memcpy(&us, pkt->buf.ptr, sizeof(us));

    y->len = ntohs(us);
    pkt->buf.ptr += 2;
    if ((size_t)(pkt->buf.data + 2 + pkt->buf.size - pkt->buf.ptr) < y->len) {
        strcpy(name, "invalid data len");
        goto err;
    }
    rdataEnd = pkt->buf.ptr + y->len;
    switch (y->type) {
    case DNS_TYPE_TXT: {
        char *p = pkt->buf.ptr;
        if (y->len == 0) goto err;
        while (p < rdataEnd) {
            unsigned int length = (unsigned char)*p++;
            if ((size_t)(rdataEnd - p) < length) goto err;
            p += length;
        }
        y->data.txt = ns_malloc(y->len);
        memcpy(y->data.txt, pkt->buf.ptr, y->len);
        pkt->buf.ptr = rdataEnd;
        break;
    }
    case DNS_TYPE_A:
        { struct sockaddr_in *saPtr = (struct sockaddr_in *)&(y->data.sa);
            if (y->len != 4) goto err;
            saPtr->sin_family = AF_INET;
            memcpy(&(saPtr->sin_addr), pkt->buf.ptr, 4);
            pkt->buf.ptr += 4;
            break;
        }
    case DNS_TYPE_AAAA:
        { struct sockaddr_in6 *saPtr = (struct sockaddr_in6 *)&(y->data.sa);
            if (y->len != 16) goto err;
            saPtr->sin6_family = AF_INET6;
            memcpy(&(saPtr->sin6_addr), pkt->buf.ptr, 16);
            pkt->buf.ptr += 16;
            break;
        }

    case DNS_TYPE_MX:
        if (y->len < 3) goto err;
        y->data.mx = ns_calloc(1, sizeof(dnsMX));
        memcpy(&us, pkt->buf.ptr, sizeof(us));
        y->data.mx->preference = ntohs(us);
        pkt->buf.ptr += 2;
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.mx->name = ns_strcopy(name);
        break;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        /* offset = (pkt->buf.ptr - pkt->buf.data) - 2; */
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.name = ns_strdup(name);
        break;
    case DNS_TYPE_NAPTR:
        if (y->len < 8) goto err;
        y->data.naptr = ns_calloc(1, sizeof(dnsNAPTR));
        memcpy(&us, pkt->buf.ptr, sizeof(us));
        y->data.naptr->order = (short)ntohs(us);
        pkt->buf.ptr += 2;
        memcpy(&us, pkt->buf.ptr, sizeof(us));
        y->data.naptr->preference = (short)ntohs(us);
        pkt->buf.ptr += 2;
        /* flags */
        if (dnsParseString(pkt, &y->data.naptr->flags) < 0) {
            strcpy(name, "invalid NAPTR flags len");
            goto err;
        }
        /* service */
        if (dnsParseString(pkt, &y->data.naptr->service) < 0) {
            strcpy(name, "invalid NAPTR service len");
            goto err;
        }
        /* regexp */
        if (dnsParseString(pkt, &y->data.naptr->regexp) < 0) {
            strcpy(name, "invalid NAPTR regexp len");
            goto err;
        }
        /* replace */
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.naptr->replace = ns_strdup(name);
        break;
    case DNS_TYPE_SOA:
        y->data.soa = ns_calloc(1, sizeof(dnsSOA));
        /* MNAME */
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.soa->mname = ns_strdup(name);
        /* RNAME */
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.soa->rname = ns_strdup(name);
        if (pkt->buf.ptr + 20 > pkt->buf.data + 2 + pkt->buf.size) {
            strcpy(name, "invalid SOA data len");
            goto err;
        }
        memcpy(&ul, pkt->buf.ptr, sizeof(ul));
        y->data.soa->serial = ntohl(ul);
        pkt->buf.ptr += 4;
        memcpy(&ul, pkt->buf.ptr, sizeof(ul));
        y->data.soa->refresh = ntohl(ul);
        pkt->buf.ptr += 4;
        memcpy(&ul, pkt->buf.ptr, sizeof(ul));
        y->data.soa->retry = ntohl(ul);
        pkt->buf.ptr += 4;
        memcpy(&ul, pkt->buf.ptr, sizeof(ul));
        y->data.soa->expire = ntohl(ul);
        pkt->buf.ptr += 4;
        memcpy(&ul, pkt->buf.ptr, sizeof(ul));
        y->data.soa->ttl = ntohl(ul);
        pkt->buf.ptr += 4;
        break;

    case DNS_TYPE_ANY:   /* fall through */
    case DNS_TYPE_HINFO: /* fall through */
    case DNS_TYPE_MINFO: /* fall through */
    case DNS_TYPE_OPT:   /* fall through */
    case DNS_TYPE_SRV:   /* fall through */
    case DNS_TYPE_WKS:   /* fall through */
    default:
        pkt->buf.ptr = rdataEnd;
        break;
    }
    if (pkt->buf.ptr != rdataEnd) {
        strcpy(name, "invalid RDATA length");
        goto err;
    }
  rec:
    dnsRecordLog(y, 9, "Record parsed: ");
    return y;
  err:
    {
        Ns_Log(Warning, "nsdns: malformed DNS record: %s", name);
        dnsRecordFree(y);
    }
    return 0;

}

dnsPacket *dnsParsePacket(unsigned char *packet, size_t size)
{
    int i;
    dnsPacket *pkt;
    dnsRecord *rec;

    pkt = dnsParseHeader(packet, size);
    if (pkt == NULL) return NULL;
    if (pkt->qdcount != 1) goto err;
    for (i = 0; i < pkt->qdcount; i++) {
        if (!(rec = dnsParseRecord(pkt, 1))) {
            goto err;
        }
        dnsRecordAppend(&pkt->qdlist, rec);
    }
    if (pkt->qdlist == 0) {
        goto err;
    }
    for (i = 0; i < pkt->ancount; i++) {
        if (!(rec = dnsParseRecord(pkt, 0))) {
            goto err;
        }
        dnsRecordAppend(&pkt->anlist, rec);
    }
    for (i = 0; i < pkt->nscount; i++) {
        if (!(rec = dnsParseRecord(pkt, 0))) {
            goto err;
        }
        dnsRecordAppend(&pkt->nslist, rec);
    }
    for (i = 0; i < pkt->arcount; i++) {
        if (!(rec = dnsParseRecord(pkt, 0))) {
            goto err;
        }
        dnsRecordAppend(&pkt->arlist, rec);
    }
    return pkt;
  err:
    dnsPacketLog(pkt, -1, "Parse error: ");
    dnsPacketFree(pkt, 2);
    return 0;

}

void dnsEncodeName(dnsPacket *pkt, char *name, int compress)
{
    dnsEncodeGrow(pkt, ((name != NULL) ? strlen(name) + 2u : 1u), "name");
    if (name != 0) {
        unsigned int c;
        int          k = 0;

        while (name[k]) {
            int      i, len;
            dnsName *nm;

            for (len = 0; (c = UCHAR(name[k + len])) != 0 && c != '.'; len++) {
                ;
            }
            if (!len || len > 63) {
                break;
            }
            /*
             * Find already saved domain name
             */
            for (nm = pkt->nmlist; compress && nm; nm = nm->next) {
                if (nm->offset >= 0 && nm->offset < 16384 && !strcasecmp(nm->name, &name[k])) {
                    dnsEncodePtr(pkt, nm->offset);
                    return;
                }
            }
            /* Save name part for future reference */
            nm = (dnsName *) ns_calloc(1, sizeof(dnsName));
            nm->next = pkt->nmlist;
            pkt->nmlist = nm;
            nm->name = ns_strdup(&name[k]);
            nm->offset = pkt->buf.ptr - pkt->buf.data - 2 < 16384
                         ? (short)(pkt->buf.ptr - pkt->buf.data - 2) : -1;
            /* Encode name part inline */
            *pkt->buf.ptr++ = (char)((len & 0x3F));
            for (i = 0; i < len; i++) {
                *pkt->buf.ptr++ = name[k++];
            }
            if (name[k] == '.') {
                k++;
            }
        }
    }
    *pkt->buf.ptr++ = 0;
}

void dnsEncodeHeader(dnsPacket *pkt)
{
    uint16_t header[7];
    pkt->buf.size = (unsigned short)(pkt->buf.ptr - pkt->buf.data - 2);
    header[0] = htons(pkt->buf.size);
    header[1] = htons(pkt->id);
    header[2] = htons(pkt->u);
    header[3] = htons(pkt->qdcount);
    header[4] = htons(pkt->ancount);
    header[5] = htons(pkt->nscount);
    header[6] = htons(pkt->arcount);
    memcpy(pkt->buf.data, header, sizeof(header));
}

void dnsEncodePtr(dnsPacket *pkt, int offset)
{
    *pkt->buf.ptr++ = (char)(0xC0 | (offset >> 8));
    *pkt->buf.ptr++ = (char)(offset & 0xFF);
}

void dnsEncodeShort(dnsPacket *pkt, int num)
{
    uint16_t us = htons((unsigned short) num);
    memcpy(pkt->buf.ptr, &us, sizeof(us));
    pkt->buf.ptr += 2;
}

void dnsEncodeLong(dnsPacket *pkt, unsigned long num)
{
    uint32_t ul = htonl((unsigned long) num);
    memcpy(pkt->buf.ptr, &ul, sizeof(ul));
    pkt->buf.ptr += 4;
}

void dnsEncodeData(dnsPacket *pkt, void *ptr, int len)
{
    dnsEncodeGrow(pkt, (size_t)len, "data");
    memcpy(pkt->buf.ptr, ptr, (unsigned) len);
    pkt->buf.ptr += len;
}

void dnsEncodeString(dnsPacket *pkt, char *str)
{
    size_t len = (str != 0) ? strlen(str) : 0;
    dnsEncodeGrow(pkt, len + 1, "string");
    *pkt->buf.ptr++ = (char)UCHAR(len);
    if (len != 0u) {
        memcpy(pkt->buf.ptr, str, len);
        pkt->buf.ptr += len;
    }
}

void dnsEncodeBegin(dnsPacket *pkt)
{
    /* Mark offset where the record begins */
    pkt->buf.rec = pkt->buf.ptr;
    dnsEncodeShort(pkt, 0);
}

void dnsEncodeEnd(dnsPacket *pkt)
{
    unsigned short us = htons(pkt->buf.ptr - pkt->buf.rec - 2);
    memcpy(pkt->buf.rec, &us, sizeof(us));
}

void dnsEncodeRecord(dnsPacket *pkt, dnsRecord *list)
{
    dnsEncodeGrow(pkt, 12, "pkt:hdr");
    for (; list; list = list->next) {
        dnsEncodeName(pkt, list->name, 1);
        dnsEncodeGrow(pkt, 26, "pkt:data");
        dnsEncodeShort(pkt, (int)list->type);
        dnsEncodeShort(pkt, list->class);
        dnsEncodeLong(pkt, list->ttl);
        dnsEncodeBegin(pkt);
        switch (list->type) {
        case DNS_TYPE_TXT:
            dnsEncodeGrow(pkt, list->len, "pkt:txt");
            dnsEncodeData(pkt, list->data.txt, list->len);
            break;
        case DNS_TYPE_A:
            { struct sockaddr_in *saPtr = (struct sockaddr_in *)&(list->data.sa);
                dnsEncodeData(pkt, &(saPtr->sin_addr), 4);
                break;
            }
        case DNS_TYPE_AAAA:
            { struct sockaddr_in6 *saPtr = (struct sockaddr_in6 *)&(list->data.sa);
                dnsEncodeData(pkt, &(saPtr->sin6_addr), 16);
                break;
            }
        case DNS_TYPE_MX:
            dnsEncodeShort(pkt, list->data.mx->preference);
            dnsEncodeName(pkt, list->data.mx->name, 1);
            break;
        case DNS_TYPE_SOA:
            dnsEncodeName(pkt, list->data.soa->mname, 1);
            dnsEncodeName(pkt, list->data.soa->rname, 1);
            dnsEncodeGrow(pkt, 20, "pkt:soa");
            dnsEncodeLong(pkt, list->data.soa->serial);
            dnsEncodeLong(pkt, list->data.soa->refresh);
            dnsEncodeLong(pkt, list->data.soa->retry);
            dnsEncodeLong(pkt, list->data.soa->expire);
            dnsEncodeLong(pkt, list->data.soa->ttl);
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
            dnsEncodeName(pkt, list->data.name, 1);
            break;
        case DNS_TYPE_NAPTR:
            dnsEncodeShort(pkt, list->data.naptr->order);
            dnsEncodeShort(pkt, list->data.naptr->preference);
            dnsEncodeString(pkt, list->data.naptr->flags);
            dnsEncodeString(pkt, list->data.naptr->service);
            dnsEncodeString(pkt, list->data.naptr->regexp);
            dnsEncodeName(pkt, list->data.naptr->replace, 0);
            break;

        case DNS_TYPE_ANY:   /* fall through */
        case DNS_TYPE_HINFO: /* fall through */
        case DNS_TYPE_MINFO: /* fall through */
        case DNS_TYPE_OPT:   /* fall through */
        case DNS_TYPE_SRV:   /* fall through */
        case DNS_TYPE_WKS:   /* fall through */
            break;
        }
        dnsEncodeEnd(pkt);
    }
}

void dnsEncodePacket(dnsPacket *pkt)
{
    dnsEncodePacketLimit(pkt, 65535);
}

/* Stop at a record boundary, and write counts for the records actually sent. */
void dnsEncodePacketLimit(dnsPacket *pkt, size_t limit)
{
    dnsRecord *record;
    dnsRecord *sections[3] = {pkt->anlist, pkt->nslist, pkt->arlist};
    uint16_t counts[3] = {0, 0, 0};
    uint16_t saved[3] = {pkt->ancount, pkt->nscount, pkt->arcount};
    unsigned short flags = pkt->u;
    int section;

    while (pkt->nmlist != NULL) {
        dnsName *next = pkt->nmlist->next;
        ns_free(pkt->nmlist->name);
        ns_free(pkt->nmlist);
        pkt->nmlist = next;
    }
    pkt->buf.ptr = pkt->buf.data + DNS_HEADER_LEN + 2;
    pkt->buf.rec = NULL;
    for (record = pkt->qdlist; record != NULL; record = record->next) {
        dnsEncodeName(pkt, record->name, 1);
        dnsEncodeGrow(pkt, 4, "question");
        dnsEncodeShort(pkt, (int)record->type);
        dnsEncodeShort(pkt, record->class);
    }
    for (section = 0; section < 3; section++) {
        for (record = sections[section]; record != NULL; record = record->next) {
            dnsRecord single = *record;
            size_t offset = (size_t)(pkt->buf.ptr - pkt->buf.data);
            single.next = NULL;
            dnsEncodeRecord(pkt, &single);
            if ((size_t)(pkt->buf.ptr - pkt->buf.data) - 2 > limit) {
                pkt->buf.ptr = pkt->buf.data + offset;
                DNS_SET_TC(pkt->u, 1);
                goto header;
            }
            counts[section]++;
        }
    }
header:
    pkt->ancount = counts[0];
    pkt->nscount = counts[1];
    pkt->arcount = counts[2];
    dnsEncodeHeader(pkt);
    pkt->ancount = saved[0];
    pkt->nscount = saved[1];
    pkt->arcount = saved[2];
    pkt->u = flags;
}

void dnsEncodeGrow(dnsPacket *pkt, size_t size, const char *UNUSED(proc))
{
    size_t offset = (size_t)(pkt->buf.ptr - pkt->buf.data);
    size_t roffset = pkt->buf.rec != NULL ? (size_t)(pkt->buf.rec - pkt->buf.data) : 0;
    if (offset + size >= pkt->buf.allocated) {
        pkt->buf.allocated = offset + size + 256;
        /* Ns_Log(Debug,"grow: %x: before: %x, %d,%d,%d",pkt,pkt->buf.data,offset,size,pkt->buf.allocated); */
        pkt->buf.data = ns_realloc(pkt->buf.data, pkt->buf.allocated);
        /* Ns_Log(Debug,"grow: %s: %x: after: %x, %d,%d,%d",proc,pkt,pkt->buf.data,offset,size,pkt->buf.allocated); */
        pkt->buf.ptr = &pkt->buf.data[offset];
        if (pkt->buf.rec != 0) {
            pkt->buf.rec = &pkt->buf.data[roffset];
        }
    }
}

dnsPacket *dnsPacketCreateReply(dnsPacket *req)
{
    dnsRecord *rec;
    dnsPacket *pkt = NULL;

    if (!req || !req->qdlist) {
        return 0;
    }
    pkt = ns_calloc(1, sizeof(dnsPacket));
    pkt->id = req->id;
    DNS_SET_QR(pkt->u, 1);
    DNS_SET_AA(pkt->u, 1);
    DNS_SET_RD(pkt->u, DNS_GET_RD(req->u));
    pkt->buf.allocated = DNS_REPLY_SIZE;
    pkt->buf.data = ns_calloc(1, pkt->buf.allocated);
    /* Ns_Log(Debug,"allocr[%d]: %x: %x",getpid(),pkt,pkt->buf.data); */
    /*  Copy query record(s) */
    for (rec = req->qdlist; rec; rec = rec->next) {
        dnsPacketAddRecord(pkt, &pkt->qdlist, &pkt->qdcount, dnsRecordCreate(rec));
    }
    return pkt;
}

dnsPacket *dnsPacketCreateQuery(const char *name, dnsType_t type)
{
    dnsPacket *pkt = NULL;

    if (name == 0) {
        return 0;
    }
    pkt = ns_calloc(1, sizeof(dnsPacket));
    pkt->id = (unsigned short)((unsigned long) pkt % (unsigned long) name);
    DNS_SET_RD(pkt->u, 1);
    pkt->buf.allocated = DNS_REPLY_SIZE;
    pkt->buf.data = ns_calloc(1, pkt->buf.allocated);
    /* Ns_Log(Debug,"allocq[%d]: %x: %x",getpid(),pkt,pkt->buf.data); */
    if (name != 0) {
        dnsRecord *rec = dnsRecordCreate(NULL);
        rec->name = ns_strdup(name);
        rec->nsize = (short)strlen(name);
        rec->class = DNS_CLASS_INET;
        rec->type = DNS_TYPE_A;

        dnsPacketAddRecord(pkt, &pkt->qdlist, &pkt->qdcount, rec);
        if (type != 0) {
            rec->type = type;
        }
    }
    return pkt;
}

void dnsPacketLog(dnsPacket *pkt, int level, const char *text, ...)
{
    dnsRecord *y;
    Tcl_DString ds;
    va_list ap;

    if (level > dnsDebug) {
        return;
    }
    va_start(ap, text);

    Tcl_DStringInit(&ds);
    Ns_DStringPrintf(&ds, "nsdns: ");
    Ns_DStringVPrintf(&ds, text, ap);
    Ns_DStringPrintf(&ds, " HEADER: [%04X] ID=%u, OP=%d, QR=%d, AA=%d, RD=%d, RA=%d, TC=%d, RCODE=%d, "
                     "QUERY=%u, ANSWER=%u, NS=%u, ADDITIONAL=%u, LEN=%d",
                     pkt->u,
                     pkt->id,
                     DNS_GET_OPCODE(pkt->u),
                     DNS_GET_QR(pkt->u),
                     DNS_GET_AA(pkt->u),
                     DNS_GET_RD(pkt->u),
                     DNS_GET_RA(pkt->u),
                     DNS_GET_TC(pkt->u),
                     DNS_GET_RCODE(pkt->u), pkt->qdcount, pkt->ancount, pkt->nscount, pkt->arcount, pkt->buf.size);
    Ns_DStringPrintf(&ds, " QUESTION SECTION: ");
    for (y = pkt->qdlist; y; y = y->next)
        dnsRecordDump(&ds, y);
    Ns_DStringPrintf(&ds, " ANSWER SECTION: ");
    for (y = pkt->anlist; y; y = y->next)
        dnsRecordDump(&ds, y);
    Ns_DStringPrintf(&ds, " NAMESERVER SECTION: ");
    for (y = pkt->nslist; y; y = y->next)
        dnsRecordDump(&ds, y);
    Ns_DStringPrintf(&ds, " ADDITIONAL SECTION: ");
    for (y = pkt->arlist; y; y = y->next)
        dnsRecordDump(&ds, y);
    Ns_Log(level < 0 ? Error : Notice, "%s", ds.string);
    Tcl_DStringFree(&ds);
}

void dnsPacketFree(dnsPacket *pkt, dnsType_t UNUSED(type))
{
    if (pkt == 0) {
        return;
    }
    dnsRecordDestroy(&pkt->qdlist);
    dnsRecordDestroy(&pkt->nslist);
    dnsRecordDestroy(&pkt->arlist);
    dnsRecordDestroy(&pkt->anlist);
    while (pkt->nmlist) {
        dnsName *next = pkt->nmlist->next;
        ns_free(pkt->nmlist->name);
        ns_free(pkt->nmlist);
        pkt->nmlist = next;
    }
    /* Ns_Log(Debug,"free[%d]: %d: %x: %x",getpid(),type,pkt,pkt->buf.data); */
    ns_free(pkt->buf.data);
    ns_free(pkt);
}

int dnsPacketAddRecord(dnsPacket *UNUSED(pkt), dnsRecord **list, uint16_t *count, dnsRecord *rec)
{
    /* Do not allow duplicate or broken records */
    if (rec == NULL) return -1;
    if (dnsRecordSearch(*list, rec, 0)) {
        dnsRecordFree(rec);
        return -1;
    }
    dnsRecordAppend(list, rec);
    (*count)++;
    return 0;
}

int dnsPacketInsertRecord(dnsPacket *UNUSED(pkt), dnsRecord **list, uint16_t *count, dnsRecord *rec)
{
    /* Do not allow duplicate or broken records */
    if (rec == NULL) return -1;
    if (dnsRecordSearch(*list, rec, 0)) {
        dnsRecordFree(rec);
        return -1;
    }
    dnsRecordInsert(list, rec);
    (*count)++;
    return 0;
}

const char *dnsTypeStr(dnsType_t type)
{
    int i = 0;
    while (dnsTypes[i].name) {
      if (type == dnsTypes[i].type) {
          return dnsTypes[i].name;
      }
      i++;
    }
    return "unknown";
}

dnsType_t dnsType(const char *name)
{
    int i = 0;
    while (dnsTypes[i].name) {
      if (!strcasecmp(name, dnsTypes[i].name)) {
          return dnsTypes[i].type;
      }
      i++;
    }
    return 0;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
