/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "ciphers.h"


int init_det_symmetric(int local_key_size, int operation_mode) {
    return openssl_init(local_key_size, operation_mode);
}

int init_auth(int key_size, int tag_size, int operation_mode) {
    return auth_init(key_size, tag_size, operation_mode);
}


int encode_det_symmetric(unsigned char* key, uint8_t *iv, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;
    
    res = openssl_encode(key, iv, dest, src, src_size);
    if (res <= 0) exit_error("[ciphers] encode_det_symmetric: Encode Error -> openssl_encode return %d\n", res);

    return res;
}

int decode_det_symmetric(unsigned char* key, uint8_t *iv, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;

    res = openssl_decode(key, iv, dest, src, src_size);
    if (res <= 0) {exit_error("[ciphers] decode_det_symmetric: Decode Error -> openssl_encode return %d\n", res);}

    return res;
}

int encode_auth(unsigned char* key, uint8_t *iv, int iv_size, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;
    
    res = auth_encode(key, iv, iv_size, dest, src, src_size, mac);
    if (res <= 0) exit_error("[ciphers] encode_auth: Encode Error -> auth_encode return %d\n", res);

    return res;
}

int decode_auth(unsigned char* key, uint8_t *iv, int iv_size, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;

    res = auth_decode(key, iv, iv_size, dest, src, src_size, mac);
    // if (res <= 0) { exit_error("[ciphers] decode_auth: Decode Error -> auth_decode return %d\n", res);}

    return res;
}

