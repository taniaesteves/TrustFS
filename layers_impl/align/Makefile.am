AUTOMAKE_OPTIONS = subdir-objects

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

noinst_LTLIBRARIES = libalign.la

libalign_la_SOURCES = alignfuse.c drivers/nopalign.c drivers/blockalign.c drivers/batch_blockalign.c 

libalign_la_CFLAGS = -Wall $(CXXFLAGS)
