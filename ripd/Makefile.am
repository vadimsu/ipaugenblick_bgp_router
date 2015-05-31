## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS) -L/usr/lib/ipaugenblick

noinst_LIBRARIES = librip.a
sbin_PROGRAMS = ripd

librip_a_SOURCES = \
	ripd.c rip_zebra.c rip_interface.c rip_debug.c rip_snmp.c \
	rip_routemap.c rip_peer.c rip_offset.c

noinst_HEADERS = \
	ripd.h rip_debug.h rip_interface.h

ripd_SOURCES = \
	rip_main.c $(librip_a_SOURCES)

ripd_LDADD = ../lib/libzebra.la @LIBCAP@ -lipaugenblickservice -lrte_eal -lrte_mempool -lrte_ring -lrte_malloc -lrte_timer -ldl

examplesdir = $(exampledir)
dist_examples_DATA = ripd.conf.sample

EXTRA_DIST = RIPv2-MIB.txt

