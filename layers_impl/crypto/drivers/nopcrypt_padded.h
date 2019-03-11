/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __NOCRYPT_PADDED_H__
#define __NOCRYPT_PADDED_H__

#include "../../../logging/logdef.h"
#include "../../../layers_conf/layers_def.h"
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../../layers_conf/SFSConfig.h"

#define NOP_PADSIZE 28

int nop_encode_padded(unsigned char* dest, const unsigned char* src, int size, void* ident);

int nop_decode_padded(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t nop_get_file_size_padded(const char* path, off_t origin_size, struct fuse_file_info* fi,
                               struct fuse_operations nextlayer);

int nop_get_cyphered_block_size_padded(int origin_size);

uint64_t nop_get_cyphered_block_offset_padded(uint64_t origin_size);

void nop_padded_init(int block_size);

off_t nop_get_truncate_size_padded(off_t size);

#endif /* __NOCRYPT_PADDED_H__ */
