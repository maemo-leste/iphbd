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
bin_PROGRAMS = iphbd
noinst_PROGRAMS = hbtest
lib_LTLIBRARIES = libiphb.la

iphbd_SOURCES = iphbd.c
iphbd_CFLAGS = $(DBUS_CFLAGS)
iphbd_LDADD = $(DBUS_LIBS)

hbtest_SOURCES = hbtest.c
hbtest_LDADD = libiphb.la

libiphb_la_SOURCES = libiphb.c
libiphb_la_LDFLAGS = $(AM_LDFLAGS)

iphbdinclude_HEADERS = libiphb.h

pkgconfigdir = ${libdir}/pkgconfig
pkgconfig_DATA = libiphb.pc

iphbdconfdbusdir=$(sysconfdir)/dbus-1/system.d
iphbdconfdbus_DATA = ../etc/dbus-1/system.d/iphbd.conf
