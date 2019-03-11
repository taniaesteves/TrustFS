#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([SFSFuse.c])
AC_CONFIG_HEADERS([config.h])

AM_PROG_AR
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_MAKE_SET


AM_INIT_AUTOMAKE
AM_PROG_CC_C_O

# Checks for libraries.

AC_CHECK_LIB([ssl], [main])
AC_CHECK_LIB([crypto], [main])
AC_CHECK_LIB([fuse], [main])
AC_CHECK_LIB([glib-2.0], [main])
AC_CHECK_LIB([zlog], [main])
AC_CHECK_LIB([pthread], [main])
AC_CHECK_LIB([erasurecode], [main])
AC_CHECK_LIB([sgx_urts], [main])
AC_CHECK_LIB([sgx_uae_service], [main])


# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/param.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero clock_gettime ftruncate gettimeofday lchown memset mkdir mkfifo rmdir strdup strerror strstr])

AC_CONFIG_SUBDIRS([layers_impl/dedup/impls/ddumbfs_layer/ layers_impl/dedup/impls/lessfs_layer/ layers_impl/remote/impls/fuse-nfs/ layers_impl/compression/impls/fusecompress_layer/])

AC_CONFIG_FILES([Makefile sgx_utils/Makefile layers_impl/align/Makefile layers_impl/dedup/Makefile layers_impl/compression/Makefile layers_impl/loopback/Makefile layers_impl/nop/Makefile layers_impl/crypto/Makefile layers_impl/remote/Makefile layers_impl/local/Makefile])

AC_OUTPUT
