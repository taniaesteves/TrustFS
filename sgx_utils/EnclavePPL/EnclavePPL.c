/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "EnclavePPL.h"

int IV_SIZE;
int MAC_SIZE;
int KEY_SIZE;
int CIPHER_MODE;
int OPERATION_MODE;
unsigned char *IV;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;

uint32_t getKey() {

    uint32_t err, sealed_sdata_len_in;
    uint32_t sealed_sdata_len = getSealedSize(KEY_SIZE);
    uint8_t *sealed_sdata     = (uint8_t*) malloc(sizeof(uint8_t) * sealed_sdata_len);

    // check if exists
    if (load_sdata(&err, sealed_sdata, sealed_sdata_len, &sealed_sdata_len_in))
        return SGX_ERROR_UNEXPECTED;
    
    // if !exist
    if (err != 0) {
        // generate random key
        memset(SERVER_KEY, 0, KEY_SIZE);
        err = sgx_read_rand((unsigned char*)SERVER_KEY, KEY_SIZE);
        if (err != SGX_SUCCESS) { usgx_exit("sgx_read_rand", err);}

        // seal server key
        seal(SERVER_KEY, KEY_SIZE, sealed_sdata);

        // save sealed key
        if (save_sdata(&err, sealed_sdata, sealed_sdata_len))
            return EXIT_FAILURE;
    }
    // if exists
    else {
        // check sealed size
        if (sealed_sdata_len_in != sealed_sdata_len)
            return EXIT_FAILURE;

        // unseal sdata
        unseal(sealed_sdata, SERVER_KEY, KEY_SIZE);
    }
    free(sealed_sdata);
    return EXIT_SUCCESS;
}

int trusted_init_EPPL(char* client_key, int key_size, char* iv, int iv_size, int mac_size, int cipher_mode, int operation_mode) {            
    int res;

    // printf("<T-PPL> initialize_enclave_ppl\n");

    IV_SIZE         = iv_size;
    MAC_SIZE        = mac_size;
    KEY_SIZE        = key_size;  
    CIPHER_MODE     = cipher_mode;  
    OPERATION_MODE  = operation_mode;  
    
    CLIENT_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    memcpy(CLIENT_KEY, client_key, KEY_SIZE);
    SERVER_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    res = getKey(); if (res != EXIT_SUCCESS) exit_error("<T-PPL> getKey error!\n");

    if (CIPHER_MODE == T_DETERMINISTIC) {
        IV = (unsigned char*) malloc (sizeof(unsigned char) * IV_SIZE);
        memcpy(IV, iv, IV_SIZE);
        init_det_symmetric(KEY_SIZE, OPERATION_MODE);        
    } else if (CIPHER_MODE == T_AUTH_RAND) {
        init_auth(KEY_SIZE, MAC_SIZE, OPERATION_MODE);
    } else         
        exit_error("<T-PPL> trusted_init_EPPL: ERROR: Unkown cipher_mode\n");
    
    
    return 0;
}

void trusted_clear_EPPL() {
    free(CLIENT_KEY);
    free(SERVER_KEY);
    if (CIPHER_MODE == T_DETERMINISTIC) free(IV);
}

int trusted_enclave_encode_det_symmetric(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {  
    // printf("<T-PPL> trusted_enclave_encode_det_symmetric: src_size=%lu\n", src_size);
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext;

    // *****************************
    // Decode data with client key
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);
    plaintext_size = decode_det_symmetric(CLIENT_KEY, IV, plaintext, src, src_size);

    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    ciphertext_size = encode_det_symmetric(SERVER_KEY, IV, ciphertext, plaintext, plaintext_size); 
    memcpy(dest, ciphertext, ciphertext_size);

    free(plaintext);
    free(ciphertext);

    // printf("<T-PPL> trusted_enclave_encode_det_symmetric: returning %lu\n", ciphertext_size);
    return ciphertext_size;
}


int trusted_enclave_decode_det_symmetric(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    // printf("<T-PPL> trusted_enclave_decode_det_symmetric: src_size=%lu\n", src_size);    
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext;

    // *****************************
    // Decode data with server key
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);    
    plaintext_size = decode_det_symmetric(SERVER_KEY, IV, plaintext, src, src_size);

    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    ciphertext_size = encode_det_symmetric(CLIENT_KEY, IV, ciphertext, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);

    free(plaintext);
    free(ciphertext);

    // printf("<T-PPL> trusted_enclave_decode_det_symmetric: returning %lu\n", ciphertext_size);
    return ciphertext_size;
}


int trusted_enclave_encode_auth_rand(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {  
    // printf("<T-PPL> trusted_enclave_encode_auth_rand: src_size=%lu\n", src_size);
    sgx_status_t err;
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext, *iv_out, *p_out_mac, *iv_in, *mac_in;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * (plaintext_size));    
    mac_in = (unsigned char*) malloc(sizeof(unsigned char) * MAC_SIZE);   
    memcpy(mac_in, &src[plaintext_size+IV_SIZE], MAC_SIZE);
    iv_in = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);   
    memcpy(iv_in, &src[plaintext_size], IV_SIZE);
    plaintext_size = decode_auth(CLIENT_KEY, iv_in, IV_SIZE, mac_in, plaintext, src, plaintext_size);

    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * MAC_SIZE);
    err = sgx_read_rand(iv_out, IV_SIZE);
    if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);    
    ciphertext_size = encode_auth(SERVER_KEY, iv_out, IV_SIZE, p_out_mac, ciphertext, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv_out, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);

    free(plaintext);
    free(ciphertext);
    free(iv_out);
    free(p_out_mac);
    free(iv_in);
    free(mac_in);

    // printf("<T-PPL> trusted_enclave_encode_auth_rand: returning %lu\n", ciphertext_size + IV_SIZE + MAC_SIZE);
    return ciphertext_size + IV_SIZE + MAC_SIZE;
}


int trusted_enclave_decode_auth_rand(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    // printf("<T-PPL> trusted_enclave_decode_auth_rand: src_size=%lu\n", src_size);
    sgx_status_t err;
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext, *iv_out, *p_out_mac, *iv_in, *mac_in;

    // *****************************
    // Decode data with server key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);  
    mac_in = (unsigned char*) malloc(sizeof(unsigned char) * MAC_SIZE);   
    memcpy(mac_in, &src[plaintext_size+IV_SIZE], MAC_SIZE);
    iv_in = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);   
    memcpy(iv_in, &src[plaintext_size], IV_SIZE);  
    plaintext_size = decode_auth(SERVER_KEY, iv_in, IV_SIZE, mac_in, plaintext, src, plaintext_size);
    if (plaintext_size <= 0) exit_error("<T-PPL> trusted_enclave_decode_auth_rand: Decode Error -> openssl_decode return %d\n", plaintext_size);
    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * MAC_SIZE);
    err = sgx_read_rand(iv_out, IV_SIZE);
    if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
    ciphertext_size = encode_auth(CLIENT_KEY, iv_out, IV_SIZE, p_out_mac, ciphertext, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv_out, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);

    free(plaintext);
    free(ciphertext);
    free(iv_in);
    free(mac_in);
    free(iv_out);
    free(p_out_mac);

    // printf("<T-PPL> trusted_enclave_decode_auth_rand: returning %lu\n", ciphertext_size + IV_SIZE + MAC_SIZE);
    return ciphertext_size + IV_SIZE + MAC_SIZE;
}
