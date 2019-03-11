/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "rand_authenticated.h"
#include "../openssl/symmetric.h"

int RAND_AUTH_BLOCKSIZE = 0;
int RAND_AUTH_TAG_SIZE = 0;
int RAND_AUTH_IV_SIZE = 0;
//there is no actually padding. This is just the additional amount of bytes after each encryption
int RAND_AUTH_PADSIZE = 0;


int rand_auth_init(char* key, int key_size, int iv_size, int tag_size, int operation_mode, int block_size) {
    DEBUG_MSG("rand_auth_init: %d -- %d -- %d -- %d -- %d\n", key_size, iv_size, tag_size, block_size, operation_mode);
    RAND_AUTH_BLOCKSIZE = block_size;
    RAND_AUTH_IV_SIZE = iv_size;
    RAND_AUTH_TAG_SIZE = tag_size;
    RAND_AUTH_PADSIZE = RAND_AUTH_IV_SIZE + RAND_AUTH_TAG_SIZE;

    int init = auth_init(key, key_size, iv_size, tag_size, operation_mode);

    if (init < 0) {
        return -1;
    } else {
        return 0;
    }
}

/**
 * Note that the size here comes without padding
 * @param dest
 * @param src
 * @param size
 * @param ident
 * @param tag
 * @return
 */
int rand_auth_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    // DEBUG_MSG("Inside random authenticated encryption %d\n", size);

    // struct key_info* inf = (struct key_info*) ident;
    unsigned char* iv = NULL;
//    TODO: esta a alocar espaço a mais
    unsigned char* cyphertext = malloc(sizeof(char)*(size + RAND_AUTH_PADSIZE));
    unsigned char* tag  = malloc(sizeof(char)*RAND_AUTH_TAG_SIZE);

    // DEBUG_MSG("Going to generate random iv for file %s at offset %d\n", inf->path, inf->offset);

//    TODO: put the rand_str in an utils.c
    iv = openssl_rand_str(RAND_AUTH_IV_SIZE);
    // DEBUG_MSG("Going to store IV %d for file %s on offset %d\n", iv, inf->path, inf->offset);

    int res = auth_encode(iv, cyphertext, src, size, tag);

    memcpy(dest, cyphertext, res);
    memcpy(&dest[res], iv, RAND_AUTH_IV_SIZE);
    memcpy(&dest[res+RAND_AUTH_IV_SIZE], tag, RAND_AUTH_TAG_SIZE);

    free(cyphertext);
    free(iv);
    free(tag);

    // DEBUG_MSG("Inside random encoding %d, returning size %d\n", size, size + RAND_AUTH_PADSIZE);

    return res + RAND_AUTH_PADSIZE;

}

/**
 * Note that here the size comes with both padding (iv + tag)
 * @param dest
 * @param src
 * @param size
 * @param ident
 * @param tag
 * @return
 */
int rand_auth_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    // DEBUG_MSG("Inside random authenticated decryption: %d\n", size);

//    TODO está a alocar espaço a mais: so precisa do ciphertext_size
    unsigned char* plaintext = malloc(sizeof(char)*size);
    unsigned char* iv = malloc(sizeof(char)*RAND_AUTH_IV_SIZE);
    unsigned char* tag = malloc(sizeof(char)*RAND_AUTH_TAG_SIZE);

    int ciphertext_size = size - RAND_AUTH_IV_SIZE - RAND_AUTH_TAG_SIZE;

    // DEBUG_MSG("Inside random authenticated decryption before memcpy size %d, size - IV_SIZE - TAG_SIZE %d\n", size, ciphertext_size);

    memcpy(iv, &src[ciphertext_size], RAND_AUTH_IV_SIZE);
    memcpy(tag, &src[ciphertext_size+RAND_AUTH_IV_SIZE], RAND_AUTH_TAG_SIZE);

    // DEBUG_MSG("Inside random decoding after memcpy %d\n", ciphertext_size);
    // DEBUG_MSG("iv %s key\n", iv);

    int res = auth_decode(iv, plaintext, src, ciphertext_size, tag);

    if (res < 0) {
        return -1;
    }

    memcpy(dest, plaintext, res);

    free(plaintext);
    free(iv);
    free(tag);

    // DEBUG_MSG("Inside random authenticate decryption %d, returning res %d\n", ciphertext_size, res);

    return res;
}

off_t rand_auth_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi_in, struct fuse_operations nextlayer) {
    uint64_t nr_complete_blocks = origin_size / (RAND_AUTH_BLOCKSIZE + RAND_AUTH_PADSIZE);
    int last_incomplete_block_size = origin_size % (RAND_AUTH_BLOCKSIZE + RAND_AUTH_PADSIZE);
    // uint64_t last_block_address = origin_size - last_incomplete_block_size;
    int last_block_real_size = 0;

    // We have original size but must get the real size of the last block which may be padded
    // DEBUG_MSG("Got size %s original size is %lu last block size is %d\n", path, origin_size, last_incomplete_block_size);

    
    if (last_incomplete_block_size > 0) {
        /*
        char aux_cyphered_buf[last_incomplete_block_size];
        unsigned char aux_plain_buf[last_incomplete_block_size];
        struct fuse_file_info* fi;
        int res;

        if (fi_in != NULL) {
            fi = fi_in;
        } else {
            fi = malloc(sizeof(struct fuse_file_info));

            // DEBUG_MSG("before open %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
            //           origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

            // TODO: add -D_GNU_SOURCE for O_LARGEFILE
            fi->flags = O_RDONLY;
            res = nextlayer.open(path, fi);

            if (res == -1) {
                // DEBUG_MSG("Failed open %s original size is %lu last block size is %d, last_block_address is %llu\n",
                //           path, origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return res;
            }
        }

        // read the block and decode to understand the number of bytes actually written
        res = nextlayer.read(path, aux_cyphered_buf, last_incomplete_block_size, last_block_address, fi);

        if (res < last_incomplete_block_size) {
            // DEBUG_MSG("Failed write %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
            //           origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
            return -1;
        }

        if (fi_in == NULL) {
            res = nextlayer.release(path, fi);

            if (res == -1) {
                // DEBUG_MSG("Failed close %s original size is %lu last block size is %d, last_block_address is %llu\n",
                //           path, origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return -1;
            }
            free(fi);
        }

        last_block_real_size = rand_auth_decode(aux_plain_buf, (unsigned char*)aux_cyphered_buf, last_incomplete_block_size, NULL);
        */
       last_block_real_size = last_incomplete_block_size - RAND_AUTH_PADSIZE;
    }

    // DEBUG_MSG("size for file %s , last block real size is %d and file real size is %lu.\n", path, last_block_real_size,
    //           nr_complete_blocks * (RAND_AUTH_BLOCKSIZE) + last_block_real_size);

    return nr_complete_blocks * RAND_AUTH_BLOCKSIZE + last_block_real_size;
}


int rand_auth_get_cyphered_block_size(int origin_size) {
    // DEBUG_MSG("rand_auth_get_cyphered_block_size: %d -- %d -- %d\n", origin_size, RAND_AUTH_BLOCKSIZE, RAND_AUTH_PADSIZE);
    int offset_block_aligned = origin_size;
    int chunks = (origin_size / RAND_AUTH_BLOCKSIZE);
    if ((origin_size % RAND_AUTH_BLOCKSIZE) != 0) {
        chunks++;
    }

    return offset_block_aligned + (RAND_AUTH_PADSIZE*chunks);
}

uint64_t rand_auth_get_cyphered_block_offset(uint64_t origin_offset) {
    // DEBUG_MSG("RAND_AUTH_BLOCKSIZE is  %d.\n", RAND_AUTH_BLOCKSIZE);

    uint64_t blockid = origin_offset / RAND_AUTH_BLOCKSIZE;

    return blockid * (RAND_AUTH_BLOCKSIZE + RAND_AUTH_PADSIZE);
}

off_t rand_auth_get_truncate_size(off_t size) {
    uint64_t nr_blocks = size / RAND_AUTH_BLOCKSIZE;
    uint64_t extra_bytes = size % RAND_AUTH_BLOCKSIZE;

    off_t truncate_size = nr_blocks * (RAND_AUTH_BLOCKSIZE + RAND_AUTH_PADSIZE);

    if (extra_bytes > 0) {
        truncate_size += rand_auth_get_cyphered_block_size(extra_bytes);
    }

    // DEBUG_MSG("truncating file sfuse to #lu\n", truncate_size);
    return truncate_size;
}

int rand_auth_clean() {
    return auth_clean();
}


//Batch processing methods
int rand_auth_get_cycle_block_size(int origin_size, int is_last_cycle, int mode) {
    return auth_get_cycle_block_size(origin_size, is_last_cycle, mode, RAND_AUTH_BLOCKSIZE, RAND_AUTH_PADSIZE);
}

int rand_auth_get_cycle_block_offset(int cycle) {
    return auth_get_cycle_block_offset(cycle, RAND_AUTH_BLOCKSIZE, RAND_AUTH_PADSIZE);
}

int rand_auth_get_total_decoding_cycles(int size) {
    return auth_get_total_decoding_cycles(size, RAND_AUTH_BLOCKSIZE, RAND_AUTH_PADSIZE);
}

int rand_auth_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle) {
    return auth_get_encrypted_chunk_size(encrypted_size, is_last_cycle, RAND_AUTH_BLOCKSIZE, RAND_AUTH_PADSIZE);
}

int rand_auth_get_plaintext_block_offset(int cycle) {
    return auth_get_plaintext_block_offset(cycle, RAND_AUTH_BLOCKSIZE);
}


int rand_auth_get_cyphered_chunk_size() {
    // DEBUG_MSG("RAND_AUTH_GET_CYPHERED_CHUNK_SIZE is  %d.\n", RAND_AUTH_BLOCKSIZE);
    return RAND_AUTH_BLOCKSIZE+RAND_AUTH_PADSIZE;
}