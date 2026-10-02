# Shared helpers; all assertions live in .test files.
if {[namespace exists ::dnsTest]} {return}
package require tcltest 2.2
namespace eval ::dnsTest {
    variable directory [file dirname [info script]]
    variable fixture {}
}
::tcltest::testConstraint tcl9 [expr {[package vcompare [info patchlevel] 9.0] >= 0}]
::tcltest::testConstraint naviserver [expr {[info commands ns_info] ne ""}]
::tcltest::testConstraint nsdns [expr {[info commands ns_dns] ne ""}]
::tcltest::testConstraint moduleInfo [expr {[info commands ns_server] ne "" && ![catch {ns_server modules}]}]
::tcltest::testConstraint transport [expr {[info commands ns_config] ne "" && [ns_config -bool test transport 0]}]
::tcltest::testConstraint ipv6 [expr {[::tcltest::testConstraint transport] && [ns_config test family] == 6}]
::tcltest::testConstraint ipv4 [expr {[::tcltest::testConstraint transport] && [ns_config test family] == 4}]
::tcltest::testConstraint fixtureProcess [expr {[::tcltest::testConstraint transport] && [file executable [info nameofexecutable]]}]
::tcltest::testConstraint connchan [expr {[info commands ns_connchan] ne "" && [ns_config -bool test connchan 0]}]
::tcltest::testConstraint tcludp [expr {![catch {package require udp 1.0.5}]}]

# Older tcludp releases do not support IPv6. Probe only when available.
set udpFamily [::tcltest::testConstraint tcludp]
if {$udpFamily && [::tcltest::testConstraint ipv6]} {
    set udpFamily [expr {![catch {udp_open 0 ipv6} udpProbe]}]
    if {$udpFamily} {close $udpProbe}
}
::tcltest::testConstraint udpFamily $udpFamily
unset udpFamily

proc ::dnsTest::query {name type {edns 0}} {
    set wire [binary format S* [list 1234 256 1 0 0 $edns]]
    foreach label [split $name .] {append wire [binary format c [string length $label]] $label}
    append wire \x00 [binary format S* [list $type 1]]
    if {$edns} {append wire \x00 [binary format S* {41 4096 0 0 0}]}
    return $wire
}
proc ::dnsTest::skipName {wire offset} {
    while 1 {
        binary scan $wire @${offset}cu length
        incr offset
        if {!$length} {return $offset}
        if {($length & 192) == 192} {return [incr offset]}
        incr offset $length
    }
}
proc ::dnsTest::answers {wire} {
    binary scan $wire S6 header
    lassign $header id flags qd an ns ar
    if {$id != 1234 || !($flags & 32768) || ($flags & 15)} {error "unexpected DNS header $header"}
    set offset 12
    for {set i 0} {$i < $qd} {incr i} {set offset [expr {[skipName $wire $offset] + 4}]}
    set result {}
    for {set i 0} {$i < $an} {incr i} {
        set offset [skipName $wire $offset]
        binary scan $wire @${offset}S2IS fields ttl length
        incr offset 10
        lappend result [list [lindex $fields 0] [binary encode hex [string range $wire $offset [expr {$offset+$length-1}]]]]
        incr offset $length
    }
    return $result
}
proc ::dnsTest::tcpWire {wire {malformed 0}} {
    set channel [ns_connchan connect -timeout 3 [ns_config test host] [ns_config test port]]
    set key $channel
    nsv_set dnsTest $key [dict create data {} done 0]
    try {
        ns_connchan write $channel [binary format S [string length $wire]]$wire
        set deadline [expr {[clock milliseconds]+3000}]
        while {[dict get [ns_connchan status $channel] sendbuffer] > 0} {
            if {[clock milliseconds] >= $deadline} {error "DNS write timed out"}
            ns_connchan write $channel {}
            after 1
        }
        # Callbacks run in another interpreter. Keep accumulated bytes in an
        # NSV so fragmented reads and a coalesced prefix/payload both work.
        ns_connchan callback -timeout 3 -receivetimeout 3 $channel [list apply {
            {channel key malformed reason} {
                set state [nsv_get dnsTest $key]
                if {[catch {
                    if {$reason ne "r"} {error "DNS socket event: $reason"}
                    set bytes [ns_connchan read $channel]
                    if {$malformed} {
                        # Readability followed by EOF proves rejection; a
                        # timeout must not count as a successful empty reply.
                        if {$bytes ne ""} {error "malformed DNS request received a reply"}
                        dict set state result {}
                        dict set state done 1
                    } else {
                        if {$bytes eq ""} {error "short DNS response"}
                        dict append state data $bytes
                        set data [dict get $state data]
                        if {[string length $data] >= 2} {
                            binary scan $data Su length
                            if {[string length $data] >= $length+2} {
                                dict set state result [string range $data 2 [expr {$length+1}]]
                                dict set state done 1
                            }
                        }
                    }
                } message]} {
                    dict set state error $message
                    dict set state done 1
                }
                nsv_set dnsTest $key $state
                return [expr {[dict get $state done] ? 2 : 1}]
            }
        } $channel $key $malformed] re
        set deadline [expr {[clock milliseconds]+4000}]
        while {![dict get [nsv_get dnsTest $key] done]} {
            if {[clock milliseconds] >= $deadline} {error "DNS response timed out"}
            after 10
        }
        set state [nsv_get dnsTest $key]
        if {[dict exists $state error]} {error [dict get $state error]}
        return [dict get $state result]
    } finally {
        ns_connchan close $channel
        nsv_unset dnsTest $key
    }
}
proc ::dnsTest::tcp {name type} {answers [tcpWire [query $name $type]]}
proc ::dnsTest::resolve {name type} {
    ns_dns resolve $name -type $type -server [ns_config test host] -port [ns_config test port]
}
proc ::dnsTest::rawUdp {wire} {
    set options [expr {[ns_config test family] == 6 ? {ipv6} : {}}]
    set channel [udp_open 0 {*}$options]
    try {
        fconfigure $channel -translation binary -buffering none -blocking 0 \
            -remote [list [ns_config test host] [ns_config test port]]
        puts -nonewline $channel $wire
        flush $channel
        set deadline [expr {[clock milliseconds]+3000}]
        while {[clock milliseconds] < $deadline} {
            set reply [read $channel]
            if {$reply ne ""} {return $reply}
            after 10
        }
        error "UDP response timed out"
    } finally {close $channel}
}
proc ::dnsTest::startFixture {} {
    variable fixture
    variable directory
    if {$fixture ne ""} {return}
    set log [::tcltest::makeFile {} upstream.log]
    set ::env(NSDNS_TEST_FIXTURE_PORT) [ns_config test upstreamport]
    set command [list [info nameofexecutable] -c -d -t [file join $directory test.nscfg] [file join $directory fixture.tcl]]
    try {
        set fixture [open [concat | $command [list 2>$log]] r+]
    } finally {unset ::env(NSDNS_TEST_FIXTURE_PORT)}
    fconfigure $fixture -blocking 0 -buffering line
    set deadline [expr {[clock milliseconds]+10000}]
    while {[clock milliseconds] < $deadline} {
        if {[gets $fixture line] >= 0} {
            if {$line eq "READY"} {return}
            error "upstream fixture: $line"
        }
        if {[eof $fixture]} {error "upstream fixture exited; see [ns_info home]/upstream.log"}
        after 10
    }
    error "upstream fixture startup timed out"
}
proc ::dnsTest::stopFixture {} {
    variable fixture
    if {$fixture ne ""} {
        catch {puts $fixture stop; flush $fixture}
        # The fixture exits on this line; close also reaps the subprocess.
        fconfigure $fixture -blocking 1
        catch {close $fixture}
        set fixture {}
        ::tcltest::removeFile upstream.log
    }
}
