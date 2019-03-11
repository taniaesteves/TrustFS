/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __AUTH_ENCRYPTION_H__
#define __AUTH_ENCRYPTION_H__

#include "../../../../logging/logdef.h"
#include "../../../../layers_conf/layers_def.h"
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../../../layers_conf/SFSConfig.h"

#define GCM 1
#define CCM 2


int auth_init(char* key, int key_size, int iv_size, int tag_size, int operation_mode);

int auth_encode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size, unsigned char* tag);

int auth_decode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size, unsigned char* tag);

int auth_clean();

void auth_handleErrors(void);

int auth_get_cycle_block_size(int origin_size, int is_last_cycle, int mode, int blk_size, int pad_size);

int auth_get_cycle_block_offset(int cycle, int blk_size, int pad_size);

int auth_get_total_decoding_cycles(int size, int blk_size, int pad_size);

int auth_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle, int blk_size, int pad_size);

int auth_get_plaintext_block_offset(int cycle, int blk_size);

void auth_set_key(unsigned char* key);

#endif
