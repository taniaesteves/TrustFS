AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = impls/ddumbfs_layer/src impls/lessfs_layer/


CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

noinst_LTLIBRARIES = libdedup.la

libdedup_la_SOURCES = dedup.c

libdedup_la_LIBADD = impls/ddumbfs_layer/src/libddumbfs.la impls/lessfs_layer/liblessfs.la

libdedup_la_CFLAGS = -Wall $(AM_CPPFLAGS) $(CXXFLAGS)

