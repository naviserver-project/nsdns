# DNS Module for NaviServer

Release **0.9.0**

This NaviServer module implements a DNS server and proxy. It serves records
from an in-memory cache or forwards requests to another DNS server and caches
the results. Commands add and remove records from the cache; no external
database is required.

Version 0.9.0 completes IPv6 transport and AAAA record handling, adds TXT
records, and reports build metadata through `ns_server modules` on cores
providing the module-information API.

## Compiling and Installing

Compile the module with:

```sh
make
```

The `dns_procs.tcl` file can be installed in `/usr/local/ns/modules/tcl`
to load on startup. It imports `/etc/hosts` into the DNS cache as `A` and
`AAAA` records, allowing the module to serve these hosts.

When switching Tcl major versions, build against the corresponding NaviServer
installation and rebuild all objects:

```sh
make clean
make NAVISERVER=/path/to/naviserver-with-tcl9
make NAVISERVER=/path/to/naviserver-with-tcl9 test
```

## IPv6 and TXT

The `address`, `proxyhost`, and `nameserver` settings accept IPv4 or IPv6
addresses. Use `address` `::1` for IPv6 loopback, or `::` for the IPv6 wildcard.
Wildcard dual-stack behavior follows NaviServer and the operating system;
use an explicit address when only one family should be exposed.
`A` and `AAAA` values must be numeric addresses of the matching family.
`dns_reload` imports IPv4 hosts as `A` and IPv6 hosts as `AAAA`, and ignores
inline comments. `PTR` records accept `ip6.arpa` names in the usual DNS form.
`CNAME` resolution retains the original query type, including `AAAA` and `TXT`.

`TXT` values are lists of one or more byte strings. Each string is at most
255 bytes; the total encoded RDATA is at most 65535 bytes. Boundaries,
empty strings, and embedded zero bytes survive storage, copying, cache
lookup, parsing, and encoding. An empty `TXT` string is `[list ""]`, not `{}`.
Use `binary format` for non-ASCII octets; for Unicode text explicitly convert
to the desired byte encoding with `encoding convertto` before adding it.

```tcl
ns_dns add example.test AAAA 2001:db8::10 3600
ns_dns add example.test TXT [list "v=spf1 -all"] 3600
ns_dns add chunks.test TXT [list "first part" "second part" ""] 3600
ns_dns add binary.test TXT [list [binary format H* 00ff]] 3600
```

Each returned `TXT` record has the form `{name TXT {string ...} ttl}`.
The `TXT` value is always a list, even for a single string. Multiple distinct
`TXT` records may exist at the same name; identical values are deduplicated.
`ns_dns del name TXT` removes that name's `TXT` records and retains other types.

```tcl
ns_dns resolve example.test -type TXT -server ::1 -port 5354
ns_dns lookup example.test AAAA
```

`resolve` supports `-server`, `-port` (default 53), `-type`, and `-timeout`.
`lookup` uses the `nameserver` setting (comma-separated addresses) and optional
`nameserverport` (default 53). Both retry truncated UDP replies over TCP.
Proxying supports IPv4/IPv6 upstreams and TCP clients. A truncated upstream
reply is not cached; a TCP client's truncated upstream reply is retried over
TCP. UDP replies respect the advertised EDNS size, or 512 bytes without
EDNS, and set `TC` when records do not fit. TCP replies are limited to 65535
bytes; an individual record that cannot fit is omitted with `TC` set.
This remains a small DNS cache/server, not a full recursive resolver or
zone-transfer implementation. Other legacy unsupported record types have
not been implemented by this update.

## Module metadata

The build sets `MODNAME=nsdns`. With a current NaviServer build system,
`Ns_ModuleGetInfo` reports name, version, Git build tag, `type=module`, and
`ABI=1` through `ns_server modules`. Older cores without that API continue
to load the module normally. Build from its Git checkout for a useful tag.

## Configuring

Here is an `nsd.tcl` excerpt for configuring the DNS module:

```tcl
ns_section      ns/server/${server}/module/nsdns
ns_param	port		5354
ns_param	address		localhost
ns_param	ttl		86400
ns_param	negativettl	3600
ns_param	cachettl	0
ns_param	readtimeout	30
ns_param	writetimeout	30
ns_param	proxytimeout	3
ns_param	proxyretries	2
ns_param	proxyhost	8.8.8.8
ns_param	proxyport	53
ns_param	defaulthost	""
ns_param        debug           0
```

| Parameter | Description |
| --- | --- |
| `port` | Local UDP/TCP listening port. |
| `address` | Local address to bind. |
| `ttl` | Default TTL for records. |
| `cachettl` | TTL to be used for cached records. |
| `negativettl` | TTL to be used for negative responses. |
| `readtimeout` | Timeout for reading. |
| `proxyhost` | Remote DNS server where to proxy requests. |
| `proxyport` | Port of the remote proxy server. |
| `proxyretries` | How many times to re-send UDP request to proxy server. |
| `proxytimeout` | How long to wait for proxy reply before timeout. |
| `debug` | Debug level, higher level more information is written in the log. |
| `defaulthost` | If no proxyhost set and query host not found reply with default host. |

## Usage

### Add records

```tcl
ns_dns add name type value... ?ttl?
```

Adds a DNS record to the cache. The name is a domain name such as
`www.cisco.com`. Wildcard names are supported:

```tcl
ns_dns add *.domain.com A 1.1.1.1
```

Requests for hosts under `domain.com` that are not in the local cache receive
the wildcard record.

| Type | Value |
| --- | --- |
| `A` | Numeric IPv4 address |
| `AAAA` | Numeric IPv6 address |
| `TXT` | Tcl list of byte strings; see [IPv6 and TXT](#ipv6-and-txt) |
| `MX` | Preference and canonical name |
| `NS`, `PTR`, `CNAME` | Domain name |
| `NAPTR` | Naming authority information (ENUM) |

Examples:

```tcl
ns_dns add www.mydomain.com A 192.168.1.1
ns_dns add ns.mydomain.com A 192.168.1.1
ns_dns add ftp.mydomain.com CNAME www.mydomain.com
ns_dns add mydomain.com NS ns.mydomain.com
ns_dns add mydomain.com MX 1 ns.mydomain.com
ns_dns add 1.2.3.4.5.6.e164.arpa NAPTR 1 100 u E2U+sip {!^.*$!sip:123456@sipproxy.net:5060!}
```

### Delete records

```tcl
ns_dns del name type ?value?
```

Deletes DNS records from the in-memory cache. For example:

```tcl
ns_dns del www.mydomain.com A
```

### List records

```tcl
ns_dns list
```

Returns all DNS records in the cache, including those cached from the remote
proxy. Example result:

```tcl
{ns.mydomain.com A 192.168.1.1 86400}
{www.mydomain.com A 192.168.1.1 86400}
{mydomain.com MX ns.mydomain.com 1 86400}
{mydomain.com NS ns.mydomain.com 86400}
{ftp.mydomain.com CNAME www.mydomain.com 86400}
```

### Flush the cache

```tcl
ns_dns flush
```

Removes all DNS records from the in-memory cache.

### Inspect pending requests

```tcl
ns_dns queue
```

Returns pending requests waiting for a reply from the remote proxy.

## Automated tests

```sh
make
make test
```

The suite supports Tcl 8.6 and Tcl 9 with `tcltest` 2.2 or later. [tests/all.test](tests/all.test) selects the `.test`
files; `TESTFLAGS` forwards normal `tcltest` selection options, for example:

```sh
make test TESTFLAGS='-file dns_records.test -match dns-txt-*'
```

`make test` runs separate IPv4 and IPv6 configurations. `NAVISERVER` selects
the installation and `NSD` can override its executable. Tests use isolated
loopback ports and Tcl upstream fixtures, without installation or public DNS.
NaviServer primitives (`ns_dns`, `ns_connchan`) cover resolver,
TCP, proxy/cache and malformed-packet tests. Helpers and the fixture are Tcl.
There is no Python or standalone C test-runner dependency.

Dependencies are declared with `tcltest` constraints in [tests/support.tcl](tests/support.tcl):

| Constraint | Dependency |
| --- | --- |
| `tcl9` | Tcl 9 or later (byte-sequence validation) |
| `naviserver`, `nsdns` | NaviServer commands and the loaded module |
| `connchan` | `ns_connchan` command and the `nssock` driver |
| `moduleInfo` | `ns_server modules` is available |
| `transport` | the selected loopback family can bind |
| `ipv4`, `ipv6` | the active usable transport family |
| `fixtureProcess` | transport and an executable nsd for the Tcl fixture |
| `tcludp` | optional udp package, version 1.0.5 or later |
| `udpFamily` | `tcludp` can open the selected address family |

Only direct raw-UDP/EDNS tests require `tcludp`. The ordinary UDP resolver
and UDP-to-TCP retry tests use `ns_dns` and run without it. Unavailable IPv6
or optional packages skip dependent tests and appear in `tcltest`'s summary.
Missing `tcltest` or a broken module load is a harness error. Test failures
produce a nonzero make exit status. Expected malformed-packet diagnostics
in the server log are not test failures.

## Manual testing

Below is output from dig utility about the configuration
provided in the above example.

```text
% dig @localhost  -p 5354 -t any openacs.org

; <<>> DiG 9.10.3-P4 <<>> @localhost -p 5354 -t any openacs.org
; (3 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34376
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;openacs.org.			IN	ANY

;; ANSWER SECTION:
openacs.org.		6422	IN	NS	ns1.wu-wien.ac.at.
openacs.org.		6422	IN	NS	ns2.wu-wien.ac.at.
openacs.org.		6422	IN	A	137.208.116.31
openacs.org.		6422	IN	AAAA	2001:628:404:74::31
openacs.org.		6422	IN	MX	10 smtp.openacs.org.
openacs.org.		6422	IN	SOA	ns0.wu-wien.ac.at. postmaster.wu-wien.ac.at. 2016041101 3600 1800 604800 3600

;; Query time: 0 msec
;; SERVER: ::1#5354(::1)
;; WHEN: Mon Apr 25 21:43:31 CEST 2016
;; MSG SIZE  rcvd: 205
```

## Authors

- Vlad Seryakov  -  <vlad@crystalballinc.com>
- Gustaf Neumann  -  <neumann@wu-wien.ac.at>

## Licensing

This project is licensed under the Mozilla Public License, v. 2.0.
A copy of the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/) is available online.
