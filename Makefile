ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsdns.so

#
# Objects to build.
#
OBJS     = nsdns.o dns.o

#
# Modules to install
#
PROCS   = nsmib_procs.tcl nsradius_procs.tcl

INSTALL += install-procs

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done

include  $(NAVISERVER)/include/Makefile.module


