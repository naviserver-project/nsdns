# Tcl-only upstream fixture. nsdns supplies UDP/TCP transport and truncation.
ns_dns add remote.test AAAA 2001:db8::30 600
ns_dns add remote.test TXT [list upstream "" [binary format H* 00ff]] 600
ns_dns add large.remote.test TXT [list [string repeat t 255] [string repeat u 255] [string repeat v 255]] 600
foreach label {0 1 2 3 4 5 6 7 8 9 10 11 pin delete flush} {
    ns_dns add $label.budget.test A 192.0.2.40 600
}
for {set i 0} {$i < 8} {incr i} {
    ns_dns add $i.bytes.test TXT [list [string repeat b 255] [string repeat c 255] [string repeat d 255] [string repeat e 255] [string repeat f 255]] 600
}
ns_dns add expire.test TXT short 1
for {set i 0} {$i < 12} {incr i} {ns_dns add many.test TXT $i 600}
puts READY
flush stdout
gets stdin
exit
