AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = impls/fusecompress_layer/


CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`  -I/opt/intel/sgxsdk/include 

noinst_LTLIBRARIES = libcompression.la

libcompression_la_SOURCES = drivers/compress_driver.c compression.c 

libcompression_la_LIBADD = impls/fusecompress_layer/libfusecompress.la $(top_srcdir)/sgx_utils/libsgxutils.la

libcompression_la_CFLAGS = -Wall $(CXXFLAGS)

