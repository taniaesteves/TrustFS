/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __CONVERGENT_ENCRYPTION_H__
#define __CONVERGENT_ENCRYPTION_H__

#include <openssl/sha.h>
#include "det_authenticated.h"
#include "../../../../utils/utils.h"

#define sha1 0
#define sha256 1
#define sha512 2

int conv_init(char* key, int key_size, unsigned char* arg_iv, int iv_size, int tag_size, int operation_mode, int block_size);

int conv_encode(unsigned char* dest, const unsigned char* src, int size, void* ident);

int conv_decode(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t conv_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi, struct fuse_operations nextlayer);

int conv_get_cyphered_block_size(int origin_size);

uint64_t conv_get_cyphered_block_offset(uint64_t origin_offset);

off_t conv_get_truncate_size(off_t size);

int conv_clean();

//Batch processing methods
int conv_get_cycle_block_size(int origin_size, int is_last_cycle, int mode);

int conv_get_cycle_block_offset(int cycle);

int conv_get_total_decoding_cycles(int size);

int conv_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle);

int conv_get_plaintext_block_offset(int cycle);

int conv_get_cyphered_chunk_size();


#endif
