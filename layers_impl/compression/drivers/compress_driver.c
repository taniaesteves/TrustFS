/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "compress_driver.h"

int TC_CLIENT_CIPHER_MODE;
int TC_CIPHER_BLOCKSIZE;
int TC_COMPRESS_BLOCKSIZE;

sgx_enclave_id_t global_eid_c;
static pthread_mutex_t eid_c_mutex  = PTHREAD_MUTEX_INITIALIZER;


/* clean and destroy SGX enclave */
int destroy_enclave_c(sgx_enclave_id_t eid) {
	sgx_status_t ret;
    // if ((ret = trusted_clear_C(eid)) != SGX_SUCCESS) DEBUG_MSG("trustedClearC: error 0x%x\n", ret);
	if ((ret = sgx_destroy_enclave(eid)) != SGX_SUCCESS) DEBUG_MSG("sgxDestroyEnclave: cant destroy EnclaveC (error 0x%x)\n", ret );
    return ret;
}

// To load and initialize the enclave 
sgx_status_t load_and_initialize_enclave_c(sgx_enclave_id_t *eid) {    
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;

    while(1) {
        // If the loading and initialization operations are caused by power transition, 
        // we need to call sgx_destroy_enclave() first.        
        if (*eid != 0) {
            sgx_destroy_enclave(*eid);
            *eid = 0;
        }

        // Load the enclave        
        ret = _sgx_create_enclave(eid, ENCLAVE_C);
        if (ret != SGX_SUCCESS) return ret;   

        // Enter the enclave to initialize the enclave
        if (TC_CLIENT_CIPHER_MODE == DETERMINISTIC) ret = trusted_det_init_EC(*eid, &retval, TC_CIPHER_BLOCKSIZE, TC_COMPRESS_BLOCKSIZE);
        else if (TC_CLIENT_CIPHER_MODE == AUTH_RAND) ret = trusted_auth_rand_init_EC(*eid, &retval, TC_CIPHER_BLOCKSIZE, TC_COMPRESS_BLOCKSIZE);

        if (ret == SGX_ERROR_ENCLAVE_LOST) {
            DEBUG_MSG("[C] Power transition occured in initialize_enclave_cload_and_initialize_enclave_c()\n");
            continue; // Try to load and initialize the enclave again
        } else {
            // No power transilation occurs.
            // If the initialization operation returns failure, change the return value.
            if (ret == SGX_SUCCESS && retval != 0) {
                ret = SGX_ERROR_UNEXPECTED;
                destroy_enclave_c(*eid);
            }
            break;
        }
    }
    return ret;
    
}


void trusted_compress_init(int cipher_mode, int cipher_blocksize, int compress_blocksize) {
    sgx_status_t ret;
    TC_CLIENT_CIPHER_MODE        = cipher_mode;
    TC_CIPHER_BLOCKSIZE   = cipher_blocksize;
    TC_COMPRESS_BLOCKSIZE = compress_blocksize;
    
    // Create and load enclaveC
    pthread_mutex_lock(&eid_c_mutex);
    global_eid_c = 0;
    ret = load_and_initialize_enclave_c(&global_eid_c);
    if (ret != SGX_SUCCESS) { DEBUG_MSG("trusted_compress_init: load_and_initialize_enclave_c error!\n"); print_sgx_error_message(ret); exit(-1); }
    pthread_mutex_unlock(&eid_c_mutex);
}

// ---- LZO ----

int lzo1xCompress(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size) {
    int res;
    res = lzo1x_1_compress(src, src_size, dst, dst_size, wrkmem);
    return res;
}

int lzo1xDecompressSafe(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size) {
    int res;
    res = lzo1x_decompress_safe(src, src_size, dst, dst_size, wrkmem);
    return res;
}

int trustedLzo1xCompress(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size) {
    sgx_enclave_id_t current_eid = 0;
    int res=0;
    sgx_status_t ret = SGX_SUCCESS;
    size_t dest_size = src_size + src_size / 16 + 64 + 3;
    
    while(1) { 
        pthread_mutex_lock(&eid_c_mutex);
        current_eid = global_eid_c;
        
        if (TC_CLIENT_CIPHER_MODE == DETERMINISTIC) {
            ret = trusted_det_lzo1x_compress(current_eid, &res, dst, dest_size, dst_size, src, src_size, wrkmem, wrkmem_size);    
        } else if (TC_CLIENT_CIPHER_MODE == AUTH_RAND) {
            ret = trusted_auth_rand_lzo1x_compress(current_eid, &res, dst, dest_size, dst_size, src, src_size, wrkmem, wrkmem_size);    
        }
        pthread_mutex_unlock(&eid_c_mutex);
        if (ret == SGX_ERROR_ENCLAVE_LOST) {
            pthread_mutex_lock(&eid_c_mutex);
            // The loading and initialization operations happen in current thread only if 
            // there is no other thread reloads and initializes the enclave before
            if (current_eid == global_eid_c) {
                DEBUG_MSG(">>>>>>>>> [C] Power transition occured in trusted_lzo1x_1_compress()\n");
                if ((ret = load_and_initialize_enclave_c(&current_eid)) != SGX_SUCCESS) {
                    DEBUG_MSG("[C] trustedLzo1xCompress -> load_and_initialize_enclave_c error!\n"); 
                    print_sgx_error_message(ret); 
                    pthread_mutex_unlock(&eid_c_mutex);
                    exit(-1); 
                } else global_eid_c = current_eid;
            } else current_eid = global_eid_c;
            pthread_mutex_unlock(&eid_c_mutex);
        } else break; // No power transition occurs
    } 
    
    if (ret != SGX_SUCCESS) {
        DEBUG_MSG("[C] trustedLzo1xCompress -> ret != SGX_SUCCESS!\n"); 
        print_sgx_error_message(ret);
        exit(-1);
    }

    // DEBUG_MSG("[C] Exiting trustedLzo1xCompress -> return: %d with size: %d\n", res, *dst_size);
    
    return res;
}

int trustedLzo1xDecompressSafe(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size) {
    sgx_enclave_id_t current_eid = 0;
    int res;
    sgx_status_t ret = SGX_SUCCESS;

    while(1) { 
        pthread_mutex_lock(&eid_c_mutex);
        current_eid = global_eid_c;        

        // DEBUG_MSG("[C] Entering trustedLzo1xDecompressSafe -> src_size=%d dst_size=%d...\n", src_size, *dst_size);        
        if (TC_CLIENT_CIPHER_MODE == DETERMINISTIC)
            ret = trusted_det_lzo1x_decompress_safe(current_eid, &res, dst, *dst_size, dst_size, src, src_size, wrkmem, wrkmem_size);
        else if (TC_CLIENT_CIPHER_MODE == AUTH_RAND)
            ret = trusted_auth_rand_lzo1x_decompress_safe(current_eid, &res, dst, *dst_size, dst_size, src, src_size, wrkmem, wrkmem_size);
    	pthread_mutex_unlock(&eid_c_mutex);
        if (ret == SGX_ERROR_ENCLAVE_LOST) {
            pthread_mutex_lock(&eid_c_mutex);
            // The loading and initialization operations happen in current thread only if 
            // there is no other thread reloads and initializes the enclave before
            if (current_eid == global_eid_c) {
                DEBUG_MSG(">>>>>>>>> [C] Power transition occured in trusted_lzo1x_1_compress()\n");
                if ((ret = load_and_initialize_enclave_c(&current_eid)) != SGX_SUCCESS) {
                    DEBUG_MSG("[C] trustedLzo1xDecompressSafe -> load_and_initialize_enclave_c error!\n"); 
                    print_sgx_error_message(ret); 
                    pthread_mutex_unlock(&eid_c_mutex);
                    exit(-1); 
                } else global_eid_c = current_eid;
            } else current_eid = global_eid_c;
            pthread_mutex_unlock(&eid_c_mutex);
        } else break; // No power transition occurs
    } 
    
    if (ret != SGX_SUCCESS) {
        DEBUG_MSG("[C] trustedLzo1xDecompressSafe -> ret != SGX_SUCCESS!\n"); 
        print_sgx_error_message(ret);
        exit(-1);
    }

    // DEBUG_MSG("Exiting trustedLzo1xDecompressSafe -> return: %d with size: %d\n", res, *dst_size);
    return res;
}

void trusted_compress_clean() {
    pthread_mutex_lock(&eid_c_mutex);
    trusted_clear_EC(global_eid_c);
    destroy_enclave_c(global_eid_c);
    pthread_mutex_unlock(&eid_c_mutex);
}
