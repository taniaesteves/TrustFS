/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __OPENSSL_SYMMETRIC_H__
#define __OPENSLL_SYMMETRIC_H__

#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "../../../../logging/logdef.h"

#define CBC 1
#define CTR 2

int openssl_init(char* key, int block_size,  int operation_mode);

int openssl_encode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size);

int openssl_decode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size);

int openssl_clean();

unsigned char* openssl_rand_str(int length);

int openssl_get_padding_size(int operation_mode);

void handleErrors(void);

int openssl_get_cycle_block_size(int origin_size, int is_last_cycle, int mode, int blk_size, int pad_size);

int openssl_get_cycle_block_offset(int cycle, int blk_size, int pad_size);

int openssl_get_total_decoding_cycles(int size, int blk_size, int pad_size);

int openssl_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle, int blk_size, int pad_size);

int openssl_get_plaintext_block_offset(int cycle, int blk_size);

#endif
