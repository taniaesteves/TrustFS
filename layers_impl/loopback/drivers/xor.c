/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "xor.h"
#include <string.h>
#include <stdlib.h>
#include "../../../utils/utils.h"

void xor_blocks(unsigned char *b1, unsigned char *b2, unsigned char *r, int len) {
    int i;
    for (i = 0; i < len; i++) {
        r[i] = (char)(b1[i] ^ b2[i]);
    }
}

void decode_xor(unsigned char *block, unsigned char **magicblocks, int size, int ndevs) {
    int i = 0;

    memcpy(block, magicblocks[0], size);

    for (i = 1; i < ndevs; i++) {
        xor_blocks(block, magicblocks[i], block, size);
    }
}

void encode_xor(const char *path, unsigned char **magicblocks, unsigned char *block, off_t offset, int size,
                int ndevs) {
    int i = 0;
    for (i = 0; i < ndevs - 1; i++) {
        generate_random_block(magicblocks[i], size);
        xor_blocks(block, magicblocks[i], block, size);
    }

    memcpy(magicblocks[i], block, size);
}
