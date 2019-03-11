/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "trusted_crypt.h"

sgx_enclave_id_t global_eid_ppl;
static pthread_mutex_t eid_ppl_mutex  = PTHREAD_MUTEX_INITIALIZER;

unsigned char *T_CLIENT_KEY;
unsigned char *T_IV;
int T_KEY_SIZE;
int T_IV_SIZE   = 0;
int T_TAG_SIZE  = 0;
int T_BLOCKSIZE = 0;
int T_CIPHER_MODE;
int T_OPERATION_MODE;

/* clean and destroy SGX enclave */
int destroy_enclave_ppl(sgx_enclave_id_t eid) {
	sgx_status_t ret;
    if ((ret = trusted_clear_EPPL(eid)) != SGX_SUCCESS) DEBUG_MSG("trustedClearPPL: error 0x%x\n", ret);
	if ((ret = sgx_destroy_enclave(eid)) != SGX_SUCCESS) DEBUG_MSG("sgxDestroyEnclave: cant destroy EnclavePPL (error 0x%x)\n", ret );
    return ret;
}
int trusted_crypt_clean() {
    if (T_CIPHER_MODE == TRUSTED_DET_SYMMETRIC) free(T_IV);
    free(T_CLIENT_KEY);
    pthread_mutex_lock(&eid_ppl_mutex);
    destroy_enclave_ppl(global_eid_ppl);
    pthread_mutex_unlock(&eid_ppl_mutex);
    return 0;
}

// To load and initialize the enclave 
sgx_status_t load_and_initialize_enclave_ppl(sgx_enclave_id_t *eid) {
    DEBUG_MSG("[PPL] Inside load_and_initialize_enclave_ppl\n");
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;

    while(1) {
        // If the loading and initialization operations are caused by power transition, 
        // we need to call sgx_destroy_enclave() first.
        // if (*eid != 0) sgx_destroy_enclave(*eid);
        if (*eid != 0) {
            sgx_destroy_enclave(*eid);
            *eid = 0;
        }

        // Load the enclave
        ret = _sgx_create_enclave(eid, ENCLAVE_PPL);
        if (ret != SGX_SUCCESS) return ret;   

        // Enter the enclave to initialize the enclave
        ret = trusted_init_EPPL(*eid, &retval, T_CLIENT_KEY, T_KEY_SIZE, T_IV, T_IV_SIZE, T_TAG_SIZE, T_CIPHER_MODE, T_OPERATION_MODE);
        if (ret == SGX_ERROR_ENCLAVE_LOST) {
            DEBUG_MSG("[PPL] Power transition occured in trusted_init_EPPL()\n");
            continue; // Try to load and initialize the enclave again
        } else {
            DEBUG_MSG("[PPL] load_and_initialize_enclave_ppl: ret=%d\n", ret);
            // No power transilation occurs.
            // If the initialization operation returns failure, change the return value.
            if (ret == SGX_SUCCESS && retval != 0) {
                ret = SGX_ERROR_UNEXPECTED;
                destroy_enclave_ppl(*eid);
            }
            break;
        }
    }
    return ret;
    
}

void trusted_crypt_init(char *client_key, int key_size, char* iv, int iv_size, int tag_size, int cipher_mode, int operation_mode, int block_size) {
    pthread_mutex_lock(&eid_ppl_mutex);  
    global_eid_ppl = 0;
    sgx_status_t ret;

    T_CLIENT_KEY = (unsigned char*) malloc (sizeof(unsigned char) * key_size);
    memcpy(T_CLIENT_KEY, client_key, key_size);

    T_KEY_SIZE            = key_size;
    T_IV_SIZE     = iv_size;
    T_TAG_SIZE    = tag_size;
    T_BLOCKSIZE   = block_size;
    T_CIPHER_MODE         = cipher_mode;
    T_OPERATION_MODE      = operation_mode;

    if (T_CIPHER_MODE == TRUSTED_DET_SYMMETRIC) {
        T_IV = (unsigned char*) malloc (sizeof(unsigned char) * T_IV_SIZE);
        memcpy(T_IV, iv, T_IV_SIZE);
    } 

    // Load and Initialize the EnclavePPL
    ret = load_and_initialize_enclave_ppl(&global_eid_ppl);
    if (ret != SGX_SUCCESS) { DEBUG_MSG("trusted_crypt_init: load_and_initialize_enclave_ppl error!\n"); print_sgx_error_message(ret); exit(-1); }printf("Exiting...PPL");
    pthread_mutex_unlock(&eid_ppl_mutex);
}

int trusted_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    sgx_enclave_id_t current_eid = 0;
    int res;
    sgx_status_t ret;
    // DEBUG_MSG("Entering trusted_encode function.\n");    
    unsigned char* tmp = (unsigned char*) malloc(sizeof(unsigned char) * (size));    
    //TODO
    while(1) { 
        pthread_mutex_lock(&eid_ppl_mutex);
        current_eid = global_eid_ppl;
        // pthread_mutex_unlock(&eid_ppl_mutex);
        
        if (T_CIPHER_MODE == TRUSTED_DET_SYMMETRIC)
            ret = trusted_enclave_encode_det_symmetric(current_eid, &res, tmp, size, (unsigned char*)src, size);
        else if (T_CIPHER_MODE == TRUSTED_AUTH_RAND)
            ret = trusted_enclave_encode_auth_rand(current_eid, &res, tmp, size, (unsigned char*)src, size);
        pthread_mutex_unlock(&eid_ppl_mutex);
        if (ret == SGX_ERROR_ENCLAVE_LOST) {
            pthread_mutex_lock(&eid_ppl_mutex);
            // The loading and initialization operations happen in current thread only if 
            // there is no other thread reloads and initializes the enclave before
            if (current_eid == global_eid_ppl) {                
                ERROR_MSG("trusted_encode: [PPL] Power transition occured\n");
                if ((ret = load_and_initialize_enclave_ppl(&current_eid)) != SGX_SUCCESS) {
                    DEBUG_MSG("trusted_encode: load_and_initialize_enclave_ppl error!\n"); 
                    print_sgx_error_message(ret); 
                    pthread_mutex_unlock(&eid_ppl_mutex);
                    exit(-1); printf("Exiting...PPL");
                } else global_eid_ppl = current_eid;
            } else current_eid = global_eid_ppl;
            pthread_mutex_unlock(&eid_ppl_mutex);
        } else break; // No power transition occurs
    } 
    DEBUG_MSG("[PPL] trusted_enclave_encode global_eid = %d, current_eid = %d\n", global_eid_ppl, current_eid);
    
    if (ret != SGX_SUCCESS) {
        DEBUG_MSG("[PPL] trusted_encode -> ret != SGX_SUCCESS! ret=%d\n"); 
        print_sgx_error_message(ret);
        exit(-1);printf("Exiting...PPL");
    }

    memcpy(dest, tmp, res);
    free(tmp);

    return res;
}

int trusted_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    sgx_enclave_id_t current_eid = 0;
    int res;
    sgx_status_t ret;
    
    int tmp_size = size;
    unsigned char* tmp = (unsigned char*) malloc(sizeof(unsigned char) * tmp_size);

    while(1) { 
        pthread_mutex_lock(&eid_ppl_mutex);
        current_eid = global_eid_ppl;
        // pthread_mutex_unlock(&eid_ppl_mutex);

        if (T_CIPHER_MODE == TRUSTED_DET_SYMMETRIC)
            ret = trusted_enclave_decode_det_symmetric(current_eid, &res, tmp, size, (unsigned char*)src, size);
        else if (T_CIPHER_MODE == TRUSTED_AUTH_RAND)
            ret = trusted_enclave_decode_auth_rand(current_eid, &res, tmp, size, (unsigned char*)src, size);
        pthread_mutex_unlock(&eid_ppl_mutex);
        if (ret == SGX_ERROR_ENCLAVE_LOST) {
            pthread_mutex_lock(&eid_ppl_mutex);
            // The loading and initialization operations happen in current thread only if 
            // there is no other thread reloads and initializes the enclave before
            if (current_eid == global_eid_ppl) {
                DEBUG_MSG("trusted_decode: [PPL] Power transition occured\n");
                if ((ret = load_and_initialize_enclave_ppl(&current_eid)) != SGX_SUCCESS) {
                    print_sgx_error_message(ret); 
                    pthread_mutex_unlock(&eid_ppl_mutex);
                    exit(-1); 
                } else global_eid_ppl = current_eid;
            } else current_eid = global_eid_ppl;
            pthread_mutex_unlock(&eid_ppl_mutex);
        } else break; // No power transition occurs
    }
    
    if (ret != SGX_SUCCESS) {
        print_sgx_error_message(ret);
        exit(-1);
    }

    memcpy(dest, tmp, res);
    free(tmp);

    return res;
}


off_t trusted_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi_in, struct fuse_operations nextlayer) {
    // DEBUG_MSG("trusted_get_file_size: %lu\n", origin_size);
    return origin_size;
}

int trusted_get_cyphered_block_size(int origin_size) {
    // DEBUG_MSG("trusted_get_cyphered_block_size: %d\n", origin_size);
    return origin_size;
}

uint64_t trusted_get_cyphered_block_offset(uint64_t origin_offset) {
    // DEBUG_MSG("trusted_get_cyphered_block_offset %d.\n", origin_offset);
    return origin_offset;
}

off_t trusted_get_truncate_size(off_t size) {
    // DEBUG_MSG("trusted_get_truncate_size: %d\n", size);
    return size;
}


//Batch processing methods
int trusted_get_cycle_block_size(int origin_size, int is_last_cycle, int mode) {
    // DEBUG_MSG("get_cycle_block_size(%d, %d, %d, %d)\n", origin_size, is_last_cycle, mode, T_BLOCKSIZE);
    int block_cycle_size = T_BLOCKSIZE;
    if (is_last_cycle == 0) {
        if ((origin_size % T_BLOCKSIZE) != 0) 
            block_cycle_size = origin_size % T_BLOCKSIZE;
    }
    return block_cycle_size;
}

int trusted_get_cycle_block_offset(int cycle) {
    return cycle * T_BLOCKSIZE;
}

int trusted_get_total_decoding_cycles(int size) {
    int complete_encrypt_cycles = (int) (size / T_BLOCKSIZE);
    if ((size % T_BLOCKSIZE) != 0) {
        complete_encrypt_cycles++;
    }
    return complete_encrypt_cycles;
}

int trusted_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle) {
    int encrypted_chunk_size = T_BLOCKSIZE;

    if (is_last_cycle == 0) {
        if ((encrypted_size % (T_BLOCKSIZE)) != 0)
            encrypted_chunk_size = encrypted_size % T_BLOCKSIZE;
    }
    return encrypted_chunk_size;
}

int trusted_get_plaintext_block_offset(int cycle) {
    return cycle * T_BLOCKSIZE;
}


int trusted_get_cyphered_chunk_size() {
    // DEBUG_MSG("TRUSTED_GET_CYPHERED_CHUNK_SIZE is  %d.\n", T_BLOCKSIZE);
    return T_BLOCKSIZE;
}