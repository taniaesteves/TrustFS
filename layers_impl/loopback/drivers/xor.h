/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/



#ifndef __XOR_H__
#define __XOR_H__

#include <sys/types.h>

void decode_xor(unsigned char *block, unsigned char **magicblocks, int size, int ndevs);

void encode_xor(const char *path, unsigned char **magicblocks, unsigned char *block, off_t offset, int size, int ndevs);

#endif /* __XOR_H__ */
