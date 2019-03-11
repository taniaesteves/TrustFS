/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "sgx_tseal.h"
#include "sgx_utils.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int seal(unsigned char *plaintext, size_t plaintext_size, unsigned char *sealed_data);
int unseal(unsigned char *sealed_data, unsigned char *unsealed_data, uint32_t unsealed_buf_size);