AUTOMAKE_OPTIONS = subdir-objects

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

noinst_LTLIBRARIES = libnop.la

libnop_la_SOURCES = nopfuse.c

libnop_la_CFLAGS = -Wall $(CXXFLAGS)
