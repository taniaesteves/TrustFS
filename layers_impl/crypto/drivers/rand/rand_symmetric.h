/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __RANDIV_SYMMETRIC_H__
#define __RANDIV_SYMMETRIC_H__

#include "../openssl/symmetric.h"
#include "../../../../logging/logdef.h"
#include "../../../../layers_conf/layers_def.h"
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../../../layers_conf/SFSConfig.h"

//#define RAND_PADSIZE 16

int rand_init(char* key, int key_size, int operation_mode, int block_size);

int rand_encode(unsigned char* dest, const unsigned char* src, int size, void* ident);

int rand_decode(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t rand_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi, struct fuse_operations nextlayer);

int rand_get_cyphered_block_size(int origin_size);

uint64_t rand_get_cyphered_block_offset(uint64_t origin_size);

int rand_clean();

off_t rand_get_truncate_size(off_t size);


// Batch processing methods

int rand_get_cycle_block_size(int origin_size, int is_last_cycle, int mode);

int rand_get_cycle_block_offset(int cycle);

int rand_get_total_decoding_cycles(int size);

int rand_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle);

int rand_get_plaintext_block_offset(int cycle);


int rand_get_cyphered_chunk_size();

#endif
