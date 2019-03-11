/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __NOCRYPT_H__
#define __NOCRYPT_H__

#include "../../../logging/logdef.h"
#include "../../../layers_conf/layers_def.h"
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int nop_encode(unsigned char* dest, const unsigned char* src, int size, void* ident);

int nop_decode(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t nop_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi,
                        struct fuse_operations nextlayer);

int nop_get_cyphered_block_size(int origin_size);
uint64_t nop_get_cyphered_block_offset(uint64_t origin_size);

off_t nop_get_truncate_size(off_t size);

#endif /* __NOCRYPT_H__ */
