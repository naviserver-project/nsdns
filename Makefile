.DEFAULT_GOAL := all

ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MODNAME  = nsdns
MOD      =  nsdns.so

#
# Objects to build.
#
MODOBJS    = nsdns.o dns.o
HDRS	= dns.h

#
# Modules to install
#
TCL = dns-procs.tcl

include  $(NAVISERVER)/include/Makefile.module



NSD ?= $(NAVISERVER)/bin/nsd
TESTFLAGS ?=
.PHONY: test
test: all
	NSDNS_TEST_FAMILY=4 $(NSD) -c -d -t $(CURDIR)/tests/test.nscfg $(CURDIR)/tests/all.test $(TESTFLAGS)
	NSDNS_TEST_FAMILY=6 $(NSD) -c -d -t $(CURDIR)/tests/test.nscfg $(CURDIR)/tests/all.test $(TESTFLAGS)
