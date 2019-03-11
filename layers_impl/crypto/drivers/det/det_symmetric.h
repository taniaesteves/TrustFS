/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __DET_SYMMETRIC_H__
#define __DET_SYMMETRIC_H__

#include "../openssl/symmetric.h"
#include "../../../../logging/logdef.h"
#include "../../../../layers_conf/layers_def.h"
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../../../layers_conf/SFSConfig.h"

//#define DET_PADSIZE 16

int det_init(char* key, unsigned char* arg_iv, int key_size, int operation_mode, int block_size);

int det_encode(unsigned char* dest, const unsigned char* src, int size, void* ident);

int det_decode(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t det_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi, struct fuse_operations nextlayer);

int det_get_cyphered_block_size(int origin_size);

uint64_t det_get_cyphered_block_offset(uint64_t origin_size);

off_t det_get_truncate_size(off_t size);

int det_clean();


// Batch processing methods

int det_get_cycle_block_size(int origin_size, int is_last_cycle, int mode);

int det_get_cycle_block_offset(int cycle);

int det_get_total_decoding_cycles(int size);

int det_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle);

int det_get_plaintext_block_offset(int cycle);

int det_get_cyphered_chunk_size();

#endif
