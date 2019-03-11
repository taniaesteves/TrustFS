/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "EnclaveC.h"

size_t CIPHER_BLOCKSIZE;
size_t CIPHER_PAD;
size_t COMPRESS_BLOCKSIZE;
int IV_SIZE=16;
int MAC_SIZE=16;
int KEY_SIZE=32;
unsigned char *SERVER_KEY;
unsigned char IV[16];

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

int trusted_det_init_EC(size_t cipher_blocksize, size_t compress_blocksize) {     
    int res;
    
    IV_SIZE  = 16;
    KEY_SIZE = 32;
    CIPHER_PAD = 0;
    CIPHER_BLOCKSIZE = cipher_blocksize - CIPHER_PAD;
    COMPRESS_BLOCKSIZE = compress_blocksize;
    
    SERVER_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    res = getKey(); if (res != EXIT_SUCCESS) exit_error("<T-C> trusted_init_EC: getKey error!\n");  

    memcpy(IV, "C53C0E2F1B0B19A", 16);

    init_det_symmetric(KEY_SIZE, 2);

    return 0;      
}

int trusted_auth_rand_init_EC(size_t cipher_blocksize, size_t compress_blocksize) {     
    int res;

    IV_SIZE  = 16;
    KEY_SIZE = 32;
    CIPHER_PAD = IV_SIZE + MAC_SIZE;
    CIPHER_BLOCKSIZE = cipher_blocksize - CIPHER_PAD;
    COMPRESS_BLOCKSIZE = compress_blocksize;

    SERVER_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    res = getKey(); if (res != EXIT_SUCCESS) exit_error("<T-C> trusted_init_EC: getKey error!\n");  

    init_auth(KEY_SIZE, MAC_SIZE, 1);
    
    return 0;      
}

void trusted_clear_EC() {
    free(SERVER_KEY);
}


int trusted_det_lzo1x_compress(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size) {    
    int res, plaintext_size, ciphertext_size, processed_size;
    long unsigned int compressed_size;
    unsigned char *plaintext, *compressed;

    // printf("<T-C> trusted_det_lzo1x_compress: src_size=%d - dst_size=%d\n", src_size, dst_size);

    plaintext_size = 0;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);    
    processed_size = 0;

    // *****************************
    // Decode data with server key
    while (processed_size < src_size) {        
        ciphertext_size = ((processed_size + CIPHER_BLOCKSIZE + CIPHER_PAD) > (src_size)) ? src_size - processed_size - CIPHER_PAD : CIPHER_BLOCKSIZE;                
        plaintext_size += decode_det_symmetric(SERVER_KEY, IV, &plaintext[plaintext_size], &src[processed_size], ciphertext_size);
        processed_size += ciphertext_size;      
    }

    // *****************************
    // Compress plaintext
    compressed = (unsigned char*) malloc(sizeof(unsigned char) * (dst_size));
    res = lzo1x_1_compress(plaintext, plaintext_size, compressed, &compressed_size, wrkmem);
    
    // *****************************
    // Encode compressed data with server key
    ciphertext_size = encode_det_symmetric(SERVER_KEY, IV, dst, compressed, compressed_size); 

    *res_size = ciphertext_size;

    free(plaintext);
    free(compressed);
    return res;
}

int trusted_det_lzo1x_decompress_safe(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size) {
    int res, plaintext_size, ciphertext_size, processed_size;
    long unsigned int decompressed_size = *res_size;
    unsigned char *plaintext, *decompressed;

    // printf("<T-C> trusted_det_lzo1x_decompress_safe: src_size=%d\n", src_size);

    // *****************************
    // Decode data with server key
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);
    plaintext_size = decode_det_symmetric(SERVER_KEY, IV, plaintext, src, src_size);

    // *****************************
    // Compress plaintext
    decompressed = (unsigned char*) malloc(sizeof(unsigned char) * (decompressed_size));
    res = lzo1x_decompress_safe(plaintext, plaintext_size, decompressed, &decompressed_size, wrkmem);
    // printf("<T-C> trusted_det_lzo1x_decompress_safe: res_size=%d & res=%d\n", decompressed_size, res);

    // *****************************
    // Encode decompressed data with server key
    processed_size = 0;
    ciphertext_size = 0;
    while (processed_size < decompressed_size) {
        plaintext_size = ((decompressed_size-processed_size) < CIPHER_BLOCKSIZE) ? decompressed_size-processed_size : CIPHER_BLOCKSIZE;
        ciphertext_size += encode_det_symmetric(SERVER_KEY, IV, &dst[ciphertext_size], &decompressed[processed_size], plaintext_size);
        processed_size  += plaintext_size;
    }
    // printf("<T-C> trusted_auth_rand_lzo1x_decompress_safe: ciphertext_size=%ld\n", ciphertext_size);

    *res_size = ciphertext_size;

    free(plaintext);
    free(decompressed);
    return res;
}

int trusted_auth_rand_lzo1x_compress(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size) {
    sgx_status_t err;
    size_t res, processed_size, plaintext_size, ciphertext_size, compressed_size;
    unsigned char *iv_in, *mac_in, *ciphertext_in, *plaintext, *compressed, *iv_out, *p_out_mac;
    // printf("<T-C> trusted_auth_rand_lzo1x_compress: src_size=%d - dst_size=%d\n", src_size, dst_size);
    
    plaintext_size = 0;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);    

    processed_size = 0;
    // printf("<T-C> trusted_auth_rand_lzo1x_compress: CIPHER_BLOCKSIZE=%d - CIPHER_PAD=%d\n", CIPHER_BLOCKSIZE, CIPHER_PAD);
    // *****************************
    // Decode data with server key
    while (processed_size < src_size) {        
        ciphertext_size = ((processed_size + CIPHER_BLOCKSIZE + CIPHER_PAD) > (src_size)) ? src_size - processed_size - CIPHER_PAD : CIPHER_BLOCKSIZE;
        iv_in           = &src[processed_size+ciphertext_size];
        mac_in          = &src[processed_size+ciphertext_size+IV_SIZE];
        ciphertext_in   = &src[processed_size];

        // printf("<T-C> trusted_auth_rand_lzo1x_compress: decode_auth src_size=%d - processed_size=%d\n", ciphertext_size, processed_size);
        plaintext_size += decode_auth(SERVER_KEY, iv_in, IV_SIZE, mac_in, &plaintext[plaintext_size], ciphertext_in, ciphertext_size);
        processed_size += ciphertext_size + CIPHER_PAD;      
    }

    // printf("<T-C> trusted_auth_rand_lzo1x_compress: after decrypt all blocks: plaintext_size=%ld\n", plaintext_size);

    // *****************************
    // Compress plaintext
    compressed = (unsigned char*) malloc(sizeof(unsigned char) * (dst_size));
    res = lzo1x_1_compress(plaintext, plaintext_size, compressed, &compressed_size, wrkmem);
    // printf("<T-C> trusted_auth_rand_lzo1x_compress: compressed_size=%d & res=%d\n", compressed_size, res);

    // *****************************
    // Encode compressed data with server key
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * MAC_SIZE);
    err = sgx_read_rand(iv_out, IV_SIZE);
    if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
    ciphertext_size = encode_auth(SERVER_KEY, iv_out, IV_SIZE, p_out_mac, dst, compressed, compressed_size);    
    if (ciphertext_size <= 0) exit_error("<T-C> Decode Error -> auth_decode return %d -> (size=%d)\n", ciphertext_size, compressed_size);

    // printf("<T-C> trusted_auth_rand_lzo1x_compress: after encode ciphertext_size=%d \n", ciphertext_size);
    
    memcpy(&dst[ciphertext_size], iv_out, IV_SIZE);
    memcpy(&dst[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);

    *res_size = ciphertext_size + IV_SIZE + MAC_SIZE;

    free(plaintext);
    free(compressed);
    free(iv_out);
    free(p_out_mac);
    
    return res;
}

int trusted_auth_rand_lzo1x_decompress_safe(uint8_t *dst, size_t dst_size, size_t *res_size, uint8_t *src, size_t src_size, uint8_t *wrkmem, size_t wrkmem_size) {
    sgx_status_t err;
    int res, plaintext_size, ciphertext_size, processed_size;
    long unsigned int decompressed_size = (*res_size) - IV_SIZE - MAC_SIZE;
    unsigned char *iv_in, *mac_in, *plaintext, *decompressed, *iv_out, *p_out_mac;

    // printf("<T-C> trusted_auth_rand_lzo1x_decompress_safe: src_size=%d\n", src_size);

    // *****************************
    // Decode data with server key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    iv_in = &src[plaintext_size];
    mac_in = &src[plaintext_size+IV_SIZE];  
    plaintext_size = decode_auth(SERVER_KEY, iv_in, IV_SIZE, mac_in, plaintext, src, plaintext_size);    
    if (plaintext_size <= 0) exit_error("<T-C> Decode Error -> auth_decode return %d -> (size=%d)\n", plaintext_size, src_size);

    // *****************************
    // Compress plaintext
    decompressed = (unsigned char*) malloc(sizeof(unsigned char) * (decompressed_size));
    // printf("<T-C> trusted_auth_rand_lzo1x_decompress_safe: size=%lu dst_size=%d\n", plaintext_size, decompressed_size);
    res = lzo1x_decompress_safe(plaintext, plaintext_size, decompressed, &decompressed_size, wrkmem);
    // printf("<T-C> trusted_auth_rand_lzo1x_decompress_safe: res_size=%d & res=%d\n", decompressed_size, res);

    // *****************************
    // Encode decompressed data with server key
    processed_size = 0;
    ciphertext_size = 0;
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * MAC_SIZE);
    while (processed_size < decompressed_size) {
        err = sgx_read_rand(iv_out, IV_SIZE);
        if (err != SGX_SUCCESS) usgx_exit("<T-C> trusted_auth_rand_lzo1x_decompress_safe: sgx_read_rand", err);

        plaintext_size = ((decompressed_size-processed_size) < CIPHER_BLOCKSIZE) ? decompressed_size-processed_size : CIPHER_BLOCKSIZE;        
        ciphertext_size += encode_auth(SERVER_KEY, iv_out, IV_SIZE, p_out_mac, &dst[ciphertext_size], &decompressed[processed_size], plaintext_size);
        // memcpy(dst, ciphertext, ciphertext_size);
        memcpy(&dst[ciphertext_size], iv_out, IV_SIZE);
        memcpy(&dst[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
        ciphertext_size += CIPHER_PAD;
        processed_size  += plaintext_size;
    }
    // printf("<T-C> trusted_auth_rand_lzo1x_decompress_safe: ciphertext_size=%ld\n", ciphertext_size);

    *res_size = ciphertext_size;

    free(plaintext);
    free(decompressed);
    free(iv_out);
    free(p_out_mac);
    return res;
}