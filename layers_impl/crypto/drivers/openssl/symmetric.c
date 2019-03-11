/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "symmetric.h"

int KEYSIZE;
unsigned char* KEY;
int OPERATION_MODE;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int openssl_get_padding_size(int operation_mode) {
    switch (operation_mode) {
        case CBC:
            return 16;
        case CTR:
            return 0;
        default:
            return 0;
    }
}

unsigned char* openssl_rand_str(int length) {
    static int mySeed = 25011984;
    char* string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
    size_t stringLen = strlen(string);
    unsigned char* randomString = NULL;

    srand(time(NULL) * length + ++mySeed);

    if (length < 1) {
        length = 1;
    }

    randomString = malloc(sizeof(char) * (length + 1));

    if (randomString) {
        short key = 0;
        int n;
        for (n = 0; n < length; n++) {
            key = rand() % stringLen;
            randomString[n] = string[key];
        }

        randomString[length] = '\0';

        return randomString;
    } else {
        ERROR_MSG("No memory");
        exit(1);
    }
}

int openssl_init(char* key, int local_key_size,  int operation_mode) {
    if (key == NULL) {        
        ERROR_MSG("(symmetric.c) - init's key argument is NULL");
        exit(1);
    }

    KEYSIZE = local_key_size;
    KEY = (unsigned char*)key;
    // define the cipher's operation mode
    OPERATION_MODE = operation_mode;
    // DEBUG_MSG("openssl_init: operation mode = %d\n", OPERATION_MODE);

    return 0;
}

const EVP_CIPHER* get_128_cipher() {
    switch (OPERATION_MODE) {
        case CBC:
            return EVP_aes_128_cbc();
        case CTR:
            return EVP_aes_128_ctr();
        default:
            return EVP_aes_128_cbc();
    }
}

const EVP_CIPHER* get_192_cipher() {
    switch (OPERATION_MODE) {
        case CBC:
            return EVP_aes_192_cbc();
        case CTR:
            return EVP_aes_192_ctr();
        default:
            return EVP_aes_192_cbc();
    }
}

const EVP_CIPHER* get_256_cipher() {
    switch (OPERATION_MODE) {
        case CBC:
            return EVP_aes_256_cbc();
        case CTR:
            return EVP_aes_256_ctr();
        default:
            return EVP_aes_256_cbc();
    }
}

const EVP_CIPHER* get_cipher() {
    switch (KEYSIZE) {
        case 16:
            return get_128_cipher();
        case 24:
            return get_192_cipher();
        default:
            return get_256_cipher();
    }
}


int openssl_encode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, get_cipher(), NULL, KEY, iv)) handleErrors();

    // DEBUG_MSG("CIPHER MODES: CBC == %d, CTR == %d\n", EVP_CIPH_CBC_MODE, EVP_CIPH_CTR_MODE);

    // DEBUG_MSG("EVP_CIPHER_CTX_mode: %d\n", EVP_CIPHER_CTX_mode(ctx));

    if (1 != EVP_EncryptUpdate(ctx, dest, &len, src, size)) handleErrors();

    /* Finalize the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, dest + len, &len)) handleErrors();
    // DEBUG_MSG("EVP_EncryptFinal_ex passed\n");
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    // DEBUG_MSG("openssl encrypt returning %d\n", ciphertext_len);

    return ciphertext_len;
}

int openssl_decode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size) {
    EVP_CIPHER_CTX* ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialize the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */

    if (1 != EVP_DecryptInit_ex(ctx, get_cipher(), NULL, KEY, iv)) handleErrors();

    // DEBUG_MSG("OPENSSL_DECODE - %d\n", EVP_CIPHER_CTX_mode(ctx));

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */

    if (1 != EVP_DecryptUpdate(ctx, dest, &len, src, size)) handleErrors();

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, dest + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int openssl_clean() { return 0; }


int openssl_get_cycle_block_size(int origin_size, int is_last_cycle, int mode, int blk_size, int pad_size) {
    // DEBUG_MSG("get_cycle_block_size(%d, %d, %d, %d, %d)\n", origin_size, is_last_cycle, mode, blk_size, pad_size);
    int block_cycle_size = blk_size;

    // Encryption
    if (mode == 0) {
        if (is_last_cycle == 0) {
            if ((origin_size % blk_size) != 0) {
                // TODO: maybe optimize this (block_cycle_size = origin_size % blk_size) ???
                block_cycle_size = (origin_size - (origin_size / blk_size) * blk_size);
            }
        }

        block_cycle_size += pad_size;
    } else {
        // Decryption
        if (is_last_cycle == 0) {
            if ((origin_size % (blk_size + pad_size)) != 0) {
                // This is incomplete since it returns the plt size + pad
                block_cycle_size = (origin_size - ((origin_size / (blk_size + pad_size)) * (blk_size + pad_size)));
            }
        }
    }

    return block_cycle_size;
}

int openssl_get_cycle_block_offset(int cycle, int blk_size, int pad_size) {
    return cycle * (blk_size + pad_size);
}

int openssl_get_total_decoding_cycles(int size, int blk_size, int pad_size) {
    // DEBUG_MSG("Inside openssl_get_decoding_cycles %d -- %d -- %d\n", size, blk_size, pad_size);
    int cycles = (size / (blk_size + pad_size));
    // DEBUG_MSG("-- cycles -- %d\n", cycles);
    if ((size % (blk_size + pad_size)) != 0) {
        cycles++;
    }

    return cycles;
}

int openssl_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle, int blk_size, int pad_size) {
    // DEBUG_MSG("openssl_get_encrypted_chunk_size - %d -- %d -- %d -- %d\n", encrypted_size, is_last_cycle, blk_size, pad_size);
    int encrypted_chunk_size = blk_size+pad_size;

    if (is_last_cycle == 0) {
        if ((encrypted_size % (blk_size+pad_size)) != 0) {
            encrypted_chunk_size = (encrypted_size-((encrypted_size/(blk_size+pad_size))*(blk_size+pad_size)));
        }
    }

    return encrypted_chunk_size;
}

int openssl_get_plaintext_block_offset(int cycle, int blk_size) {
    return cycle*blk_size;
}