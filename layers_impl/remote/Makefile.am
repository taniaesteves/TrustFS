AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = impls/fuse-nfs/fuse

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

noinst_LTLIBRARIES = libremote.la

libremote_la_SOURCES = remote.c

libremote_la_LIBADD = impls/fuse-nfs/fuse/libfusenfs.la

libremote_la_CFLAGS = -Wall $(CXXFLAGS)
