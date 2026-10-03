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

## Configuring

For resolver-only use, add the following to the NaviServer configuration.
`$server` is the existing virtual-server name. Use your preferred upstream
resolver in place of `1.1.1.1`.

```tcl
#---------------------------------------------------------------------
# nsdns nameserver support -- extra module "nsdns"
#---------------------------------------------------------------------
ns_section ns/server/$server/modules {
    ns_param nsdns nsdns
}
ns_section ns/server/$server/module/nsdns {
    ns_param port       0        ;# Disable the local UDP/TCP listener
    ns_param nameserver 1.1.1.1  ;# Upstream for ns_dns lookup
    #ns_param nameserverport 53  ;# Default upstream port; optional
}
```

After restarting, run `ns_dns lookup openacs.org TXT` in that server's Tcl
interpreter. `nameserver` must be configured for `lookup`; the module does
not import `/etc/resolv.conf`. `nameserverport` defaults to 53. The local
`port` is unrelated to outgoing lookups.

To serve local records as well, replace the module configuration block with:

```tcl
ns_section ns/server/$server/module/nsdns {
    ns_param address 127.0.0.1
    ns_param port    5354
    #ns_param proxyhost 1.1.1.1 ;# Optional forwarding of unanswered requests
    #ns_param proxyport 53     ;# Default proxy destination port
}
```

Use `address ::1` for IPv6 loopback. The `address`, `nameserver`, and
`proxyhost` settings accept IPv4 or IPv6 addresses. Wildcard dual-stack
behavior depends on NaviServer and the operating system.

### Parameters

Timeouts and TTLs below are integer seconds, not Tcl duration strings.

| Parameter | Default | Description |
| --- | --- | --- |
| `port` | `5353` | Local UDP/TCP listening port (0..65535). Set to 0 for resolver-only use; ns_dns lookup and ns_dns resolve do not use this listener. |
| `address` | Unset | Local listening address. Set an explicit IPv4 or IPv6 address, e.g. 127.0.0.1 or ::1 for loopback. When omitted, the socket API uses a wildcard address; wildcard dual-stack behavior depends on the platform. Ignored when port is 0. |
| `nameserver` | Unset | Comma-separated upstream IPv4 or IPv6 addresses used by ns_dns lookup. No servers are configured by default; the module does not read /etc/resolv.conf. ns_dns resolve instead accepts an explicit -server argument. |
| `nameserverport` | `53` | Upstream destination port (1..65535) used by ns_dns lookup. Only needed when the upstream listens on a nonstandard port. Independent of the local port and proxyport. |
| `proxyhost` | Unset | Upstream IPv4 or IPv6 DNS server for incoming requests that cannot be answered locally. Omit to disable forwarding. Independent of nameserver; requires a nonzero local port. |
| `proxyport` | `53` | Destination port of proxyhost. Applies to forwarding incoming DNS requests, not ns_dns lookup. |
| `proxytimeout` | `3` | Proxy reply timeout in seconds; also used for a TCP retry after a truncated upstream response. |
| `proxyretries` | `2` | Maximum number of UDP proxy transmission attempts, including the initial request. |
| `ttl` | `86400` | Default record TTL in seconds. A positive value overrides the default; ns_dns add can supply a per-record TTL. |
| `cachettl` | `0` | Minimum nonzero TTL in seconds for records inserted into the cache. Positive values raise shorter nonzero TTLs; 0 leaves them unchanged. |
| `negativettl` | `3600` | Legacy negative-response TTL setting in seconds. Currently read by the module but not used; setting it does not enable negative caching. |
| `readtimeout` | `30` | TCP client read timeout in seconds. |
| `writetimeout` | `30` | TCP client write timeout in seconds. |
| `threads` | `1` | Number of DNS request worker queues and threads (1..16). Used when the local listener is enabled. |
| `rcvbuf` | `0` | Local UDP socket receive and send buffer size in bytes. Despite the name, sets both SO_RCVBUF and SO_SNDBUF. 0 preserves operating-system defaults. |
| `defaulthost` | Unset | Fallback numeric address for unanswered A or AAAA queries when proxyhost is unset. Must match the requested address family. Omit to disable; does not synthesize TXT records. |
| `debug` | `0` | DNS diagnostic verbosity. Higher values produce more detail; explicitly configuring this parameter also enables the Debug(dnsd) log severity. |
| `flags` | `0` | Legacy behavior bit mask. Bit 4 (DNS_NAPTR_REGEXP) enables NAPTR regexp processing. Leave at 0 for ordinary DNS/TXT use. |

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

### Supported record types

`ns_dns add` supports all of the following types. Optional TTLs are in seconds.

| Type | Arguments after the type | Meaning |
| --- | --- | --- |
| `A` | `address ?ttl?` | Numeric IPv4 address |
| `AAAA` | `address ?ttl?` | Numeric IPv6 address |
| `TXT` | `strings ?ttl?` | Tcl list of byte strings; see below |
| `MX` | `preference exchange ?ttl?` | Mail exchanger and numeric preference |
| `NS` | `nameserver ?ttl?` | Name of an authoritative nameserver |
| `PTR` | `target ?ttl?` | Reverse lookup target; use an `in-addr.arpa` or `ip6.arpa` owner name |
| `CNAME` | `target ?ttl?` | Alias; resolution retains the requested type, including AAAA and TXT |
| `NAPTR` | `order preference flags service regexp ?replacement? ?ttl?` | Naming Authority Pointer, including ENUM records |

SOA records can be decoded, returned by lookups, and encoded by the module,
but cannot be created with `ns_dns add`. `ANY` is a query type, not an
addable record type. Other legacy record-type names do not imply implemented
record support.

```tcl
ns_dns add host.test A 192.0.2.10 3600
ns_dns add host.test AAAA 2001:db8::10 3600
ns_dns add alias.test CNAME host.test 3600
ns_dns add example.test NS host.test 3600
ns_dns add example.test MX 10 host.test 3600
ns_dns add 10.2.0.192.in-addr.arpa PTR host.test 3600
ns_dns add 1.2.3.4.5.6.e164.arpa NAPTR 1 100 u E2U+sip {!^.*$!sip:123456@sipproxy.net:5060!}
```

`dns_reload` imports IPv4 and IPv6 entries from `/etc/hosts` as A and AAAA
records and ignores inline comments. Records live in memory; re-add local
records after restarting.

#### TXT values

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

For protocols such as SPF, `lookup` and `resolve` accept `-jointxt` to return
each TXT value as one byte string instead of a list of strings. Concatenation
inserts no separators and applies independently to each record in all three
response sections. Separate TXT records remain separate, and other record
types are unchanged. Embedded zero and non-ASCII bytes are preserved.
This works with both the legacy list result and `-details` dictionaries.
The default retains string boundaries, as required by protocols such as DNS-SD;
stored records and `ns_dns find` output are not changed by a joined lookup.

```tcl
ns_dns lookup -jointxt example.org TXT
ns_dns resolve -details -jointxt -type TXT -server 1.1.1.1 example.org
# A TXT value {{v=spf1 include:_spf.example.org} { -all}} becomes:
# {v=spf1 include:_spf.example.org -all}
```

### Query upstream servers

```tcl
# Uses configured nameserver and nameserverport (default 53).
ns_dns lookup openacs.org TXT

# Detailed response and a total network deadline.
ns_dns lookup -details -timeout 2s openacs.org TXT

# Selects the destination explicitly, independently of nameserver.
ns_dns resolve chunks.test -type TXT -server ::1 -port 5354

# Preferred option-first syntax (Ns_ParseObjv).
ns_dns resolve -details -type TXT -server ::1 -port 5354 -timeout 2s chunks.test

# General DNS names can begin with a hyphen; use the option terminator.
ns_dns lookup -details -- -example.test TXT
```

Both commands use `Ns_ParseObjv`, accept `-details`, `-jointxt`, `-timeout`, and `--`,
and place options before the name. `lookup` retains its optional positional
record type. `resolve` also supports `-server`, `-port` (default 53), and `-type`;
its existing hostname-first option syntax remains supported.

Without `-details`, results retain the three-element list of answer, authority,
and additional sections, and network/query failures retain the empty result.
With `-details`, the result is a dictionary with `rcode` (numeric DNS response
code, including the EDNS extension when present), `answer`, `authority`,
`additional`, and boolean `truncated`. Record representations are unchanged.
For example, an NXDOMAIN response has `rcode 3`; SERVFAIL has `rcode 2`.
These are completed DNS responses, not Tcl errors. NOERROR is `rcode 0`;
an empty answer alone does not establish that the name is nonexistent.

Detailed queries that cannot obtain a usable response raise Tcl errors:

| Error code | Meaning |
| --- | --- |
| `NS_TIMEOUT` | Network wait or total deadline expired |
| `NSDNS NETWORK` | Address resolution, connection, or socket I/O failed |
| `NSDNS PROTOCOL MALFORMED` | DNS response could not be decoded |
| `NSDNS PROTOCOL MISMATCH` | Response did not match the query |
| `NSDNS PROTOCOL TRUNCATED` | TCP response was still truncated |
| `NSDNS CONFIG NO_NAMESERVER` | No configured upstream is available |

Use `try ... trap NS_TIMEOUT ... trap {NSDNS PROTOCOL} ... trap NSDNS ...`
to handle these categories. When attempts fail differently, the final failure
determines the reported error.

`-timeout` accepts NaviServer time values such as `100ms`, `2s`, or `0.5`.
For option-first calls and detailed calls, it bounds network waits across
retries, upstreams, and UDP-to-TCP fallback together. Zero expires immediately.
Use numeric upstream addresses for predictable timing: system resolution of
an upstream hostname is outside the socket-wait deadline mechanism.
Without an explicit timeout, configured/default per-operation waits apply.
For compatibility, hostname-first `resolve` calls without `-details` retain
their historical integer-second, per-attempt timeout (zero uses the default).

Both lookup commands retry truncated UDP replies over TCP. Neither uses the
local listening port to select its upstream.

Proxying supports IPv4/IPv6 upstreams and TCP clients. A truncated upstream
reply is not cached; a TCP client's truncated upstream reply is retried over
TCP. UDP replies respect the advertised EDNS size, or 512 bytes without
EDNS, and set TC when records do not fit. TCP replies are limited to 65535
bytes; an individual record that cannot fit is omitted with TC set. This
module is not a full recursive resolver or zone-transfer server.

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
| `nsdProcess` | NaviServer and an executable nsd for isolated startup tests |
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

With the loopback listener configured on port 5354, add records in the
server's Tcl interpreter:

```tcl
ns_dns add txt.test TXT [list "v=spf1 -all"] 3600
ns_dns add chunks.test TXT [list "first part" "second part" ""] 3600
ns_dns find chunks.test
ns_dns resolve chunks.test -type TXT -server 127.0.0.1 -port 5354
```

Then query over UDP and TCP from the shell:

```sh
dig @127.0.0.1 -p 5354 chunks.test TXT
dig @127.0.0.1 -p 5354 chunks.test TXT +tcp
```

For an IPv6 loopback listener, substitute `::1` for `127.0.0.1`.

## Module metadata

The build sets `MODNAME=nsdns`. With a current NaviServer build system,
`Ns_ModuleGetInfo` reports name, version, Git build tag, `type=module`, and
`ABI=1` through `ns_server modules`. Older cores without that API continue
to load the module normally. Build from its Git checkout for a useful tag.

## Authors

- Vlad Seryakov  -  <vlad@crystalballinc.com>
- Gustaf Neumann  -  <neumann@wu-wien.ac.at>

## Licensing

This project is licensed under the Mozilla Public License, v. 2.0.
A copy of the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/) is available online.
