/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __CIPHERS_H__
#define __CIPHERS_H__

#include "auth_encryption.h"
#include "symmetric.h"
#include <stdint.h>

#define T_AUTH_RAND 7
#define T_DETERMINISTIC 8
#define T_AUTH_RAND_DET 9

int init_det_symmetric(int local_key_size, int operation_mode);
int init_auth(int key_size, int tag_size, int operation_mode);

int encode_det_symmetric(unsigned char* key, uint8_t *iv, uint8_t *dest, uint8_t* src, size_t src_size);
int decode_det_symmetric(unsigned char* key, uint8_t *iv, uint8_t *dest, uint8_t* src, size_t src_size);

int encode_auth(unsigned char* key, uint8_t *iv, int iv_size, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size);
int decode_auth(unsigned char* key, uint8_t *iv, int iv_size, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size);

#endif