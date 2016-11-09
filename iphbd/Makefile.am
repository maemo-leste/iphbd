#
# Generic options
#
AM_CFLAGS = -Wall -Wmissing-prototypes -std=c99 -Os -g -fPIC
AM_CPPFLAGS = -I$(top_srcdir)/modules -D_GNU_SOURCE
AM_LDFLAGS = -g -Wl,--as-needed

ACLOCAL_AMFLAGS = -I m4

#
# Additional dirs
#
iphbdincludedir = @includedir@/iphbd

#
# Build targets
#
lib_LTLIBRARIES = libiphb.la

libiphb_la_SOURCES = libiphb.c
libiphb_la_LDFLAGS = $(AM_LDFLAGS) -shared

iphbdinclude_HEADERS = libiphb.h

pkgconfigdir = ${libdir}/pkgconfig
pkgconfig_DATA = libiphb.pc
