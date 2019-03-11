/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef _ENCLAVE_PPL_H_
#define _ENCLAVE_PPL_H_

#include "Ocalls.h"
#include "Seal.h"
#include "sgx_utils.h"
#include "ciphers.h"

#include <unistd.h> 
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int trusted_init_EPPL(char* client_key, int key_size, char* iv, int iv_size, int mac_size, int cipher_mode, int operation_mode);
void trusted_clear_EPPL();

int trusted_enclave_encode_det_symmetric(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int trusted_enclave_decode_det_symmetric(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);

int trusted_enclave_encode_auth_rand(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int trusted_enclave_decode_auth_rand(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);

#endif /* !_ENCLAVE_PPL_H_ */
