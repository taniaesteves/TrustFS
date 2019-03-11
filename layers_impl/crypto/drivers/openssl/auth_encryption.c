/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "auth_encryption.h"

unsigned char* KEY;
int KEY_SIZE;
int OPERATION_MODE;
int IV_SIZE;
int TAG_SIZE;


void auth_handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

const EVP_CIPHER* auth_get_128_cipher() {
    switch (OPERATION_MODE) {
        case GCM:
            return EVP_aes_128_gcm();
        case CCM:
//            return EVP_aes_128_ccm();
        default:
            return NULL;
    }
}

const EVP_CIPHER* auth_get_192_cipher() {
    switch (OPERATION_MODE) {
        case GCM:
            return EVP_aes_192_gcm();
        case CCM:
//            return EVP_aes_192_ccm();
        default:
            return NULL;
    }
}

const EVP_CIPHER* auth_get_256_cipher() {
    switch (OPERATION_MODE) {
        case GCM:
            return EVP_aes_256_gcm();
        case CCM:
//            return EVP_aes_256_ccm();
        default:
            return NULL;
    }
}

const EVP_CIPHER* auth_get_cipher() {
    switch (KEY_SIZE) {
        case 16:
            return auth_get_128_cipher();
        case 24:
            return auth_get_192_cipher();
        default:
            return auth_get_256_cipher();
    }
}

int define_ivlen() {
    switch (OPERATION_MODE) {
        case GCM:
            return EVP_CTRL_GCM_SET_IVLEN;
        case CCM:
            return EVP_CTRL_CCM_SET_IVLEN;
        default:
            return -1;
    }
}

/**
 *
 * @param mode: If mode == 0 -> get_tag; else if mode == 1 -> set_tag;
 * @return
 */
int define_tag(int mode) {
    switch (OPERATION_MODE) {
        case GCM:
            if (mode == 0) {
                return EVP_CTRL_GCM_GET_TAG;
            } else {
                return EVP_CTRL_GCM_SET_TAG;
            }
        case CCM:
            if (mode == 0) {
                return EVP_CTRL_CCM_GET_TAG;
            } else {
                return EVP_CTRL_CCM_SET_TAG;
            }
        default:
            return -1;
    }
}

int auth_init(char* key, int key_size, int iv_size, int tag_size, int operation_mode) {
    if (key == NULL) {
        ERROR_MSG("(symmetric.c) - init's key argument is NULL");
        exit(1);
    }

    KEY_SIZE = key_size;
    KEY = (unsigned char*) key;
    OPERATION_MODE = operation_mode;
    IV_SIZE = iv_size;
    TAG_SIZE = tag_size;

    // DEBUG_MSG("auth_encryption_init: operation mode = %d\n", OPERATION_MODE);

    return 0;
}

int auth_encode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size, unsigned char* tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) auth_handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, auth_get_cipher(), NULL, NULL, NULL)) auth_handleErrors();

    /* Set IV length */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, define_ivlen(), IV_SIZE, NULL)) auth_handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, KEY, iv)) auth_handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    // if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, dest, &len, src, size)) auth_handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, dest + len, &len)) auth_handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, define_tag(0), TAG_SIZE, tag)) auth_handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int auth_decode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size, unsigned char* tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) auth_handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, auth_get_cipher(), NULL, NULL, NULL)) auth_handleErrors();

    /* Set IV length.*/
    if(!EVP_CIPHER_CTX_ctrl(ctx, define_ivlen(), IV_SIZE, NULL))	auth_handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, KEY, iv)) auth_handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    // if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, dest, &len, src, size)) auth_handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, define_tag(1), TAG_SIZE, tag)) auth_handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, dest + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        // DEBUG_MSG("Decode: success\n");
        return plaintext_len;
    } else {
        /* Verify failed */
        ERROR_MSG("Decode: fail\n");
        return -1;
    }
}

int auth_clean() {
    return 0;
}

int auth_get_cycle_block_size(int origin_size, int is_last_cycle, int mode, int blk_size, int pad_size) {
//    DEBUG_MSG("get_cycle_block_size(%d, %d, %d, %d, %d)\n", origin_size, is_last_cycle, mode, blk_size, pad_size);
    int block_cycle_size = blk_size;

//  Encryption
    if (mode == 0) {
        if (is_last_cycle == 0) {
            if ((origin_size % blk_size) != 0) {
//                TODO: maybe optimize this (block_cycle_size = origin_size % blk_size) ???
                block_cycle_size = (origin_size - (origin_size / blk_size) * blk_size);
            }
        }

        block_cycle_size += pad_size;
    } else {
//      Decryption
        if (is_last_cycle == 0) {
            if ((origin_size % (blk_size + pad_size)) != 0) {
//              This is incomplete since it returns the plt size + pad
                block_cycle_size = (origin_size - ((origin_size / (blk_size + pad_size)) * (blk_size + pad_size)));
            }
        }
    }

    return block_cycle_size;
}

int auth_get_cycle_block_offset(int cycle, int blk_size, int pad_size) {
    return cycle * (blk_size + pad_size);
}

int auth_get_total_decoding_cycles(int size, int blk_size, int pad_size) {
//    DEBUG_MSG("Inside auth_get_decoding_cycles %d -- %d -- %d\n", size, blk_size, pad_size);
    int cycles = (size / (blk_size + pad_size));
//    DEBUG_MSG("-- cycles -- %d\n", cycles);
    if ((size % (blk_size + pad_size)) != 0) {
        cycles++;
    }

    return cycles;
}

int auth_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle, int blk_size, int pad_size) {
//    DEBUG_MSG("auth_get_encrypted_chunk_size - %d -- %d -- %d -- %d\n", encrypted_size, is_last_cycle, blk_size, pad_size);
    int encrypted_chunk_size = blk_size+pad_size;

    if (is_last_cycle == 0) {
        if ((encrypted_size % (blk_size+pad_size)) != 0) {
            encrypted_chunk_size = (encrypted_size-((encrypted_size/(blk_size+pad_size))*(blk_size+pad_size)));
        }
    }

    return encrypted_chunk_size;
}

int auth_get_plaintext_block_offset(int cycle, int blk_size) {
    return cycle*blk_size;
}

void auth_set_key(unsigned char* key) {
    KEY = key;
}

