/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "rand_symmetric.h"

int RAND_BLOCKSIZE = 0;
int IV_SIZE = 0;
int RAND_FINALPADSIZE = 0;
int RAND_PADSIZE = 0;


int rand_init(char* key, int key_size, int operation_mode, int block_size) {
    RAND_BLOCKSIZE = block_size;
    IV_SIZE = key_size;
    RAND_PADSIZE = openssl_get_padding_size(operation_mode);
    RAND_FINALPADSIZE = IV_SIZE + RAND_PADSIZE;

    int init_sym_val = openssl_init(key, key_size, operation_mode);

    if (init_sym_val < 0) {
        return -1;
    } else {
        return 0;
    }
}

// size here comes without pad
int rand_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    DEBUG_MSG("Inside random encoding %d\n", size);

    struct key_info* inf = (struct key_info*)ident;
    unsigned char* iv = NULL;
    unsigned char* cypherbuffer = malloc(size + RAND_PADSIZE);

    DEBUG_MSG("Going to generate random iv for file %s at offset %d\n", inf->path, inf->offset);

    iv = openssl_rand_str(IV_SIZE);
    DEBUG_MSG("Going to store IV %d for file %s on offset %d\n", iv, inf->path, inf->offset);

    int res = openssl_encode(iv, cypherbuffer, src, size);

    memcpy(dest, cypherbuffer, res);
    memcpy(&dest[res], iv, IV_SIZE);
    free(cypherbuffer);
    free(iv);

    DEBUG_MSG("Inside random encoding %d, returning size %d\n", size, res + IV_SIZE);

    return res + IV_SIZE;
}

int rand_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    DEBUG_MSG("Inside random decoding %d\n", size);

//    TODO: acho que está a alocar espaço a mais;
    unsigned char* plainbuffer = malloc(size);
    // Original size - the IV_SIZE
    int size_to_decode = size - IV_SIZE;

    DEBUG_MSG("Inside random decoding before memcpy size %d, size - IV_SIZE %d\n", size, size_to_decode);

    unsigned char iv[IV_SIZE];
    memcpy(iv, &src[size_to_decode], IV_SIZE);

    DEBUG_MSG("Inside random decoding after memcpy %d\n", size_to_decode);
    DEBUG_MSG("iv %s key\n", iv);

    int res = openssl_decode(iv, plainbuffer, src, size_to_decode);

    memcpy(dest, plainbuffer, res);
    free(plainbuffer);

    DEBUG_MSG("Inside random decoding %d, returning res %d\n", size_to_decode, res);

    return res;
}

int rand_clean() {
    int clean_symm_res = openssl_clean();
    if (clean_symm_res < 0) {
        return -1;
    } else {
        return 0;
    }
}

off_t rand_get_file_size(const char* path, off_t original_size, struct fuse_file_info* fi_in, struct fuse_operations nextlayer) {
    uint64_t nr_complete_blocks = original_size / (RAND_BLOCKSIZE + RAND_FINALPADSIZE);
    int last_incomplete_block_size = original_size % (RAND_BLOCKSIZE + RAND_FINALPADSIZE);
    uint64_t last_block_address = original_size - last_incomplete_block_size;
    int last_block_real_size = 0;

    // We have original size but must get the real size of the last block which may be padded
    DEBUG_MSG("Got size %s original size is %lu last block size is %d\n", path, original_size, last_incomplete_block_size);

    if (last_incomplete_block_size > 0) {
        char aux_cyphered_buf[last_incomplete_block_size];
        unsigned char aux_plain_buf[last_incomplete_block_size];
        struct fuse_file_info* fi;
        int res;

        if (fi_in != NULL) {
            fi = fi_in;
        } else {
            fi = malloc(sizeof(struct fuse_file_info));

            DEBUG_MSG("before open %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                      original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

            // TODO: add -D_GNU_SOURCE for O_LARGEFILE
            fi->flags = O_RDONLY;
            res = nextlayer.open(path, fi);

            if (res == -1) {
                DEBUG_MSG("Failed open %s original size is %lu last block size is %d, last_block_address is %llu\n",
                          path, original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return res;
            }
        }

        // read the block and decode to understand the number of bytes actually written
        res = nextlayer.read(path, aux_cyphered_buf, last_incomplete_block_size, last_block_address, fi);

        if (res < last_incomplete_block_size) {
            DEBUG_MSG("Failed write %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                      original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
            return -1;
        }

        if (fi_in == NULL) {
            res = nextlayer.release(path, fi);

            if (res == -1) {
                DEBUG_MSG("Failed close %s original size is %lu last block size is %d, last_block_address is %llu\n",
                          path, original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return -1;
            }
            free(fi);
        }

        last_block_real_size = rand_decode(aux_plain_buf, (unsigned char*)aux_cyphered_buf, last_incomplete_block_size, NULL);
    }

    DEBUG_MSG("size for file %s , last block real size is %d and file real size is %lu.\n", path, last_block_real_size,
              nr_complete_blocks * (RAND_BLOCKSIZE) + last_block_real_size);

    return nr_complete_blocks * RAND_BLOCKSIZE + last_block_real_size;
}

int rand_get_cyphered_block_size(int origin_size) {
    int offset_block_aligned = origin_size;
    int chunks = (origin_size / RAND_BLOCKSIZE);
    if ((origin_size % RAND_BLOCKSIZE) != 0) {
        chunks++;
    }

    if (RAND_PADSIZE > 0) {
        offset_block_aligned = origin_size / RAND_PADSIZE * RAND_PADSIZE;
    }

    return offset_block_aligned + (RAND_FINALPADSIZE*chunks);
}

uint64_t rand_get_cyphered_block_offset(uint64_t origin_offset) {
    DEBUG_MSG("RAND_BLOCKSIZE is  %d.\n", RAND_BLOCKSIZE);

    uint64_t blockid = origin_offset / RAND_BLOCKSIZE;

    return blockid * (RAND_BLOCKSIZE + RAND_FINALPADSIZE);
}

off_t rand_get_truncate_size(off_t size) {
    uint64_t nr_blocks = size / RAND_BLOCKSIZE;
    uint64_t extra_bytes = size % RAND_BLOCKSIZE;

    off_t truncate_size = nr_blocks * (RAND_BLOCKSIZE + RAND_FINALPADSIZE);

    if (extra_bytes > 0) {
        truncate_size += rand_get_cyphered_block_size(extra_bytes);
    }

    DEBUG_MSG("truncating file sfuse to #lu\n", truncate_size);
    return truncate_size;
}


// Batch processing methods

int rand_get_cycle_block_size(int origin_size, int is_last_cycle, int mode) {
    DEBUG_MSG("Rand_get_cycle_block_size(%d, %d, %d)\n", origin_size, is_last_cycle, mode);
    return openssl_get_cycle_block_size(origin_size, is_last_cycle, mode, RAND_BLOCKSIZE, RAND_FINALPADSIZE);
}

int rand_get_cycle_block_offset(int cycle) {
    return openssl_get_cycle_block_offset(cycle, RAND_BLOCKSIZE, RAND_FINALPADSIZE);
}

int rand_get_total_decoding_cycles(int size) {
    return openssl_get_total_decoding_cycles(size, RAND_BLOCKSIZE, RAND_FINALPADSIZE);
}

int rand_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle) {
    return openssl_get_encrypted_chunk_size(encrypted_size, is_last_cycle, RAND_BLOCKSIZE, RAND_FINALPADSIZE);
}

int rand_get_plaintext_block_offset(int cycle) {
    return openssl_get_plaintext_block_offset(cycle, RAND_BLOCKSIZE);
}


int rand_get_cyphered_chunk_size() {
    return RAND_BLOCKSIZE+RAND_FINALPADSIZE;
}