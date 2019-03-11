/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "rep.h"
#include <string.h>
#include <stdlib.h>

void rep_decode(unsigned char *block, unsigned char **magicblocks, int size, int ndevs) {
    memcpy(block, magicblocks[0], size);
}

void rep_encode(const char *path, unsigned char **magicblocks, unsigned char *block, off_t offset, int size,
                int ndevs) {
    int i = 0;

    for (i = 0; i < ndevs; i++) {
        memcpy(magicblocks[i], block, size);
    }
}