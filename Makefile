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
PROCS   = dns_procs.tcl

INSTALL += install-procs

include  $(NAVISERVER)/include/Makefile.module

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done



NSD ?= $(NAVISERVER)/bin/nsd
TESTFLAGS ?=
.PHONY: test
test: all
	NSDNS_TEST_FAMILY=4 $(NSD) -c -d -t $(CURDIR)/tests/test.nscfg $(CURDIR)/tests/all.test $(TESTFLAGS)
	NSDNS_TEST_FAMILY=6 $(NSD) -c -d -t $(CURDIR)/tests/test.nscfg $(CURDIR)/tests/all.test $(TESTFLAGS)
