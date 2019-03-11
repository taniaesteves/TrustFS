/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef _ENCLAVE_C_H_
#define _ENCLAVE_C_H_

#include "Ocalls.h"
#include "Seal.h"
#include "sgx_utils.h"

#include <unistd.h> 
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "minilzo.h"
#include "lzoconf.h"
#include "lzodefs.h"

#include "ciphers.h"

#include "sgx_spinlock.h"


int trusted_det_init_EC(size_t cipher_blocksize, size_t compress_blocksize);
int trusted_auth_rand_init_EC(size_t cipher_blocksize, size_t compress_blocksize);
void trusted_clear_EC();

int trusted_det_lzo1x_compress(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size);
int trusted_det_lzo1x_decompress_safe(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size);

int trusted_auth_rand_lzo1x_compress(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size);
int trusted_auth_rand_lzo1x_decompress_safe(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size);

#endif /* !_ENCLAVE_C_H_ */
