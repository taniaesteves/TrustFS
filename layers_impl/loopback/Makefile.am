AUTOMAKE_OPTIONS = subdir-objects

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

noinst_LTLIBRARIES = libloopback.la

libloopback_la_SOURCES = drivers/erasure.c drivers/rep.c drivers/xor.c multi_loopback.c

libloopback_la_CFLAGS = -Wall $(CXXFLAGS)
