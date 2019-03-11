/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __COMPRESS_DRIVER_H__
#define __COMPRESS_DRIVER_H__

#include "../../../sgx_utils/sgx_utils.h"
#include "../../../logging/logdef.h"
#include "minilzo/minilzo.h"


#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define DETERMINISTIC 3
#define AUTH_RAND 4

// ---- Init ----

// void compress_init();
void trusted_compress_init(int cipher_mode, int cipher_blocksize, int compress_blocksize);

// ---- LZO ----

int lzo1xCompress(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size);
int lzo1xDecompressSafe(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size);

int trustedLzo1xCompress(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size);
int trustedLzo1xDecompressSafe(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size);


// ---- Clean ----

void trusted_compress_clean();

#endif