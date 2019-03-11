AUTOMAKE_OPTIONS = subdir-objects

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

noinst_LTLIBRARIES = liblocal.la

liblocal_la_SOURCES = local.c

liblocal_la_CFLAGS = -Wall $(CXXFLAGS)
