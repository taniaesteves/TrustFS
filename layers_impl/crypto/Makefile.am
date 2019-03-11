AUTOMAKE_OPTIONS = subdir-objects

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`    -I/opt/intel/sgxsdk/include 

noinst_LTLIBRARIES = libsfuse.la

libsfuse_la_SOURCES = sfuse.c drivers/openssl/symmetric.c drivers/det/det_symmetric.c drivers/rand/rand_symmetric.c drivers/nopcrypt.c drivers/nopcrypt_padded.c drivers/openssl/auth_encryption.c drivers/rand/rand_authenticated.c drivers/det/det_authenticated.c drivers/det/convergent_encryption.c drivers/trusted_crypt.c 

libsfuse_la_LIBADD= $(top_srcdir)/sgx_utils/libsgxutils.la

libsfuse_la_CFLAGS = -Wall $(AM_CPPFLAGS) $(CXXFLAGS)

