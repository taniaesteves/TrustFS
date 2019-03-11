/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __RAND_AUTHENTICATED_H__
#define __RAND_AUTHENTICATED_H__

#include "../openssl/auth_encryption.h"


int rand_auth_init(char* key, int key_size, int iv_size, int tag_size, int operation_mode, int block_size);

int rand_auth_encode(unsigned char* dest, const unsigned char* src, int size, void* ident);

int rand_auth_decode(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t rand_auth_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi, struct fuse_operations nextlayer);

int rand_auth_get_cyphered_block_size(int origin_size);

uint64_t rand_auth_get_cyphered_block_offset(uint64_t origin_offset);

off_t rand_auth_get_truncate_size(off_t size);

int rand_auth_clean();

//Batch processing methods
int rand_auth_get_cycle_block_size(int origin_size, int is_last_cycle, int mode);

int rand_auth_get_cycle_block_offset(int cycle);

int rand_auth_get_total_decoding_cycles(int size);

int rand_auth_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle);

int rand_auth_get_plaintext_block_offset(int cycle);


int rand_auth_get_cyphered_chunk_size();

#endif
