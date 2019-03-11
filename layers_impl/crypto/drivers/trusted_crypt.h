/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __TRUSTED_CRYPT_H__
#define __TRUSTED_CRYPT_H__

#include "../../../logging/logdef.h"
#include "../../../layers_conf/layers_def.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#include <pthread.h>

#include "openssl/auth_encryption.h"
#include "../../../sgx_utils/sgx_utils.h"
#include "../sfuse.h"

void trusted_crypt_init(char *client_key, int key_size, char *iv, int iv_size, int tag_size, int cipher_mode, int operation_mode, int block_size);
int trusted_crypt_clean();

int trusted_encode(unsigned char* dest, const unsigned char* src, int size, void* ident);
int trusted_decode(unsigned char* dest, const unsigned char* src, int size, void* ident);

off_t trusted_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi, struct fuse_operations nextlayer);
int trusted_get_cyphered_block_size(int origin_size);
uint64_t trusted_get_cyphered_block_offset(uint64_t origin_size);
off_t trusted_get_truncate_size(off_t size);


//Batch processing methods
int trusted_get_cycle_block_size(int origin_size, int is_last_cycle, int mode);

int trusted_get_cycle_block_offset(int cycle);

int trusted_get_total_decoding_cycles(int size);

int trusted_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle);

int trusted_get_plaintext_block_offset(int cycle);


int trusted_get_cyphered_chunk_size();

#endif /* __TRUSTED_CRYPT_H__ */
