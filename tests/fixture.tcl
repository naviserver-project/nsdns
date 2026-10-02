# Tcl-only upstream fixture. nsdns supplies UDP/TCP transport and truncation.
ns_dns add remote.test AAAA 2001:db8::30 600
ns_dns add remote.test TXT [list upstream "" [binary format H* 00ff]] 600
ns_dns add large.remote.test TXT [list [string repeat t 255] [string repeat u 255] [string repeat v 255]] 600
puts READY
flush stdout
gets stdin
exit
