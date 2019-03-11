/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "sgx_urts.h"
#include "EnclavePPL/sgx_edger8r/EnclavePPL_u.h"
#include "EnclaveC/sgx_edger8r/EnclaveC_u.h"

#define TOKEN_FILENAME_PPL  "/opt/trustfs/EnclavePPL.token"
#define ENCLAVE_FILE_PPL    "/opt/trustfs/EnclavePPL.signed.so"

#define TOKEN_FILENAME_C    "/opt/trustfs/EnclaveC.token"
#define ENCLAVE_FILE_C      "/opt/trustfs/EnclaveC.signed.so"

#define ENCLAVE_PPL 0
#define ENCLAVE_C   1

int _sgx_create_enclave(sgx_enclave_id_t *eid, int enclaveType);

void print_sgx_error_message(sgx_status_t err);
