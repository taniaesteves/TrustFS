/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __LAYERSDEF_H__
#define __LAYERSDEF_H__

#ifdef __linux__
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif /* FUSE_USE_VERSION */
#endif /* __linux__ */

#if defined(_POSIX_C_SOURCE)
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
#endif

#include <stdio.h>
#include <fuse.h>
#include <stdlib.h>
#include <sys/stat.h>

// This is used by the sfuse layer drivers
struct key_info {
    const char *path;
    uint64_t offset;
};

struct encode_driver {
    int (*encode)(unsigned char *dest, const unsigned char *src, int size, void *ident);
    int (*decode)(unsigned char *dest, const unsigned char *src, int size, void *ident);
    off_t (*get_file_size)(const char *path, off_t orig_size, struct fuse_file_info *fi, struct fuse_operations nextlayer);
    int (*get_cyphered_block_size)(int orig_size);
    uint64_t (*get_cyphered_block_offset)(uint64_t orig_offset);
    off_t (*get_truncate_size)(off_t size);
    int (*copy_dbkeys)(const char *from, const char *to);
    int (*delete_dbkeys)(const char *path);
//    Batch processing methods
    int (*get_cycle_block_size)(int origin_size, int is_last_cycle, int mode);
    int (*get_cycle_block_offset)(int cycle);
    int (*get_total_decoding_cycles)(int size);
    int (*get_encrypted_chunk_size)(int encrypted_size, int is_last_cycle);
    int (*get_plaintext_block_offset)(int cycle);

//    TODO temporary
    int (*get_cyphered_chunk_size)();
};

struct align_driver {
    int (*align_read)(const char *path, char *buf, size_t size, off_t offset, void *fi,
                      struct fuse_operations nextlayer);
    int (*align_write)(const char *path, const char *buf, size_t size, off_t offset, void *fi, struct fuse_operations nextlayer);
    int (*align_create)(const char *path, mode_t mode, void *fi, struct fuse_operations nextlayer);
    int (*align_open)(const char *path, void *fi, struct fuse_operations nextlayer);
    int (*align_truncate)(const char *path, off_t size, struct fuse_file_info *fi, struct fuse_operations nextlayer);
};

struct multi_driver {
    void (*get_driver_offset)(const char *path, off_t offset, off_t *driver_offset);
    void (*get_driver_size)(const char *path, off_t offset, uint64_t *driver_size);
    void (*encode)(const char *path, unsigned char **magicblocks, unsigned char *block, off_t offset, int size, int ndevs);
    void (*decode)(unsigned char *block, unsigned char **magicblocks, int size, int ndevs);
    uint64_t (*get_file_size)(const char *path);
    void (*rename)(char *from, char *to);
    void (*create)(char *path);
    void (*clean)();
};

struct compression_driver {
    int (*compress)(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size);
    int (*decompress)(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size);
};



#endif /*__LAYERSDEF_H__*/
