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

include  $(NAVISERVER)/include/Makefile.module


