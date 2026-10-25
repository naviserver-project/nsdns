# Load numeric IPv4 and IPv6 addresses from a hosts file.
proc dns_reload {hosts} {
    if {[catch {open $hosts} fd]} {return}
    set count 0
    try {
        ns_dns flush
        while {[gets $fd line] >= 0} {
            set fields [regexp -all -inline {\S+} [lindex [split $line #] 0]]
            if {[llength $fields] < 2} {continue}
            set ipaddr [lindex $fields 0]
            set type [expr {[string first : $ipaddr] >= 0 ? "AAAA" : "A"}]
            foreach name [lrange $fields 1 end] {
                if {![catch {ns_dns add $name $type $ipaddr 0}]} {incr count}
            }
        }
    } finally {
        close $fd
    }
    ns_log Notice "nsdns: $hosts loaded, $count records"
}

if {[info commands ns_dns] ne ""} {
    dns_reload /etc/hosts
}
