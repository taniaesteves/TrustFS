/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "nopcrypt.h"

#include <string.h>

int nop_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    DEBUG_MSG("Entering nop_encode function.\n");
    // just make a copy
    memcpy(dest, src, size);

    DEBUG_MSG("Exiting nop_decode function.\n");

    return size;
}

int nop_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    DEBUG_MSG("Entering nop_decode function.\n");
    // just make a copy
    memcpy(dest, src, size);
    DEBUG_MSG("Exiting nop_decode function.\n");

    return size;
}

off_t nop_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi,
                        struct fuse_operations nextlayer) {
    return origin_size;
}

int nop_get_cyphered_block_size(int origin_size) { return origin_size; }

uint64_t nop_get_cyphered_block_offset(uint64_t origin_offset) { return origin_offset; }

off_t nop_get_truncate_size(off_t size) { return size; }
