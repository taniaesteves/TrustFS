AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = EnclavePPL EnclaveC

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0` -I/opt/intel/sgxsdk/include

noinst_LTLIBRARIES = libsgxutils.la

libsgxutils_la_SOURCES = sgx_utils.c

libsgxutils_la_LIBADD =  -L$(abs_top_builddir)/sgx_utils/EnclavePPL -lenclave_ppl -L$(abs_top_builddir)/sgx_utils/EnclaveC -lenclave_c

libsgxutils_la_CFLAGS = -Wall $(CXXFLAGS) 
