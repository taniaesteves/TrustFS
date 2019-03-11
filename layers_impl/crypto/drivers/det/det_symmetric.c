/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "det_symmetric.h"

unsigned char* IV = NULL;
int DET_BLOCKSIZE = 0;
int DET_PADSIZE = 0;


int det_init(char* key, unsigned char* arg_iv, int key_size, int operation_mode, int block_size) {
    DET_BLOCKSIZE = block_size;
    DET_PADSIZE = openssl_get_padding_size(operation_mode);
    IV = arg_iv;

    int init_sym_val = openssl_init(key, key_size, operation_mode);

    if (init_sym_val < 0) {
        return -1;
    } else {
        return 0;
    }
}

// size here comes without pad
int det_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {    
//    TODO: optimize this allocation space (currently it is allocating more than the necessary)
    unsigned char* cypherbuffer = malloc(size + DET_PADSIZE);    

    int res = openssl_encode(IV, cypherbuffer, src, size);

    memcpy(dest, cypherbuffer, res);
    free(cypherbuffer);


    return res;
}

// size here comes with pad
int det_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    // DEBUG_MSG("det_decode: Inside deterministic decoding %d\n", size);

//    TODO: optimize this allocation space (currently it is allocating more than the necessary)
    unsigned char* plainbuffer = malloc(size);    

    int res = openssl_decode(IV, plainbuffer, src, size);

    memcpy(dest, plainbuffer, res);
    free(plainbuffer);

    // DEBUG_MSG("Inside deterministic decoding %d, returning res %d\n", size, res);
    return res;
}

int det_clean() { return openssl_clean(); }

off_t det_get_file_size(const char* path, off_t original_size, struct fuse_file_info* fi_in, struct fuse_operations nextlayer) {    
    uint64_t nr_complete_blocks = original_size / (DET_BLOCKSIZE + DET_PADSIZE);
    int last_incomplete_block_size = original_size % (DET_BLOCKSIZE + DET_PADSIZE);
    uint64_t last_block_address = original_size - last_incomplete_block_size;
    int last_block_real_size = 0;

    // We have original size but must get the real size of the last block which may be padded
    DEBUG_MSG("det_get_file_size: Got size %s original size is %lu last block size is %d\n", path, original_size, last_incomplete_block_size);

    if (last_incomplete_block_size > 0) {
        char aux_cyphered_buf[last_incomplete_block_size];
        unsigned char aux_plain_buf[last_incomplete_block_size];
        struct fuse_file_info* fi;
        int res;

        if (fi_in != NULL) {
            fi = fi_in;
        } else {
            fi = malloc(sizeof(struct fuse_file_info));

            DEBUG_MSG("det_get_file_size: before open %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                      original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

            // TODO: add -D_GNU_SOURCE for O_LARGEFILE
            fi->flags = O_RDONLY;
            res = nextlayer.open(path, fi);

            if (res == -1) {
                DEBUG_MSG("det_get_file_size: Failed open %s original size is %lu last block size is %d, last_block_address is %llu\n",
                          path, original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return res;
            }
        }

        DEBUG_MSG("det_get_file_size: read %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                  original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

        // read the block and decode to understand the number of bytes actually written
        res = nextlayer.read(path, aux_cyphered_buf, last_incomplete_block_size, last_block_address, fi);

        if (res < last_incomplete_block_size) {
            DEBUG_MSG("det_get_file_size: Failed read %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                      original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
            return -1;
        }

        if (fi_in == NULL) {
            res = nextlayer.release(path, fi);

            if (res == -1) {
                DEBUG_MSG("det_get_file_size: Failed close %s original size is %lu last block size is %d, last_block_address is %llu\n",
                          path, original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return -1;
            }
            free(fi);
        }

        DEBUG_MSG("det_get_file_size: Before decode read %s original size is %lu last block size is %d, last_block_address is %llu\n",
                  path, original_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

        last_block_real_size = det_decode(aux_plain_buf, (unsigned char*)aux_cyphered_buf, last_incomplete_block_size, NULL);        
    }

    DEBUG_MSG("det_get_file_size: size for file %s , last block real size is %d and file real size is %lu.\n", path, last_block_real_size,
              nr_complete_blocks * (DET_BLOCKSIZE) + last_block_real_size);

    return nr_complete_blocks * DET_BLOCKSIZE + last_block_real_size;
}

int det_get_cyphered_block_size(int origin_size) {
    int offset_block_aligned = origin_size;
    int chunks = (origin_size / DET_BLOCKSIZE);
    if ((origin_size % DET_BLOCKSIZE) != 0) {
        chunks++;
    }

    if (DET_PADSIZE > 0) {
        offset_block_aligned = origin_size / DET_PADSIZE * DET_PADSIZE;
    }

    return offset_block_aligned + (DET_PADSIZE * chunks);
}

uint64_t det_get_cyphered_block_offset(uint64_t origin_offset) {
    uint64_t blockid = origin_offset / DET_BLOCKSIZE;

    return blockid * (DET_BLOCKSIZE + DET_PADSIZE);
}

off_t det_get_truncate_size(off_t size) {
    uint64_t nr_blocks = size / DET_BLOCKSIZE;
    uint64_t extra_bytes = size % DET_BLOCKSIZE;

    off_t truncate_size = nr_blocks * (DET_BLOCKSIZE + DET_PADSIZE);

    if (extra_bytes > 0) {
        truncate_size += det_get_cyphered_block_size(extra_bytes);
    }    
    return truncate_size;
}


/**
 *
 * @param origin_size - Original size. If mode == 0, the source's was in plaintext. If mode == 1, the source's was encrypted.
 * @param is_last_cycle - If 0, it is the last cycle of the batching process.
 * @param mode - Operation mode: mode == 0 is encryption, mode == 1 is decryption.
 * @return
 */
int det_get_cycle_block_size(int origin_size, int is_last_cycle, int mode) {    
    return openssl_get_cycle_block_size(origin_size, is_last_cycle, mode, DET_BLOCKSIZE, DET_PADSIZE);
}

int det_get_cycle_block_offset(int cycle) {
    return openssl_get_cycle_block_offset(cycle, DET_BLOCKSIZE, DET_PADSIZE);
}

int det_get_total_decoding_cycles(int size) {
    return openssl_get_total_decoding_cycles(size, DET_BLOCKSIZE, DET_PADSIZE);
}

int det_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle) {
    return openssl_get_encrypted_chunk_size(encrypted_size, is_last_cycle, DET_BLOCKSIZE, DET_PADSIZE);
}

int det_get_plaintext_block_offset(int cycle) {
    return openssl_get_plaintext_block_offset(cycle, DET_BLOCKSIZE);
}


int det_get_cyphered_chunk_size() {
    return DET_BLOCKSIZE+DET_PADSIZE;
}
