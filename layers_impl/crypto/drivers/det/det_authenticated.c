/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "det_authenticated.h"

int DET_AUTH_BLOCKSIZE = 0;
int DET_AUTH_TAG_SIZE = 0;
unsigned char* DET_AUTH_IV = NULL;
int DET_AUTH_IV_SIZE = 0;
int DET_AUTH_PAD_SIZE = 0;


int det_auth_init(char* key, int key_size, unsigned char* arg_iv, int iv_size, int tag_size, int operation_mode, int block_size) {
    DEBUG_MSG("det_auth_inti: %d -- %d -- %d -- %d\n", key_size, iv_size, tag_size, operation_mode);

    DET_AUTH_BLOCKSIZE = block_size;
    DET_AUTH_IV = arg_iv;
    DET_AUTH_IV_SIZE = iv_size;
    DET_AUTH_TAG_SIZE = tag_size;
    DET_AUTH_PAD_SIZE = DET_AUTH_TAG_SIZE;

    int init = auth_init(key, key_size, iv_size, tag_size, operation_mode);

    if (init < 0) {
        return -1;
    } else {
        return 0;
    }
}

int det_auth_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    DEBUG_MSG("Inside deterministic authenticated encryption %d\n", size);

    unsigned char* cypherbuffer = malloc(sizeof(char)*(size+DET_AUTH_PAD_SIZE));
    unsigned char* tag = malloc(sizeof(char)*DET_AUTH_TAG_SIZE);

    int res = auth_encode(DET_AUTH_IV, cypherbuffer, src, size, tag);

    if (res < 0) {
        return -1;
    }

    memcpy(dest, cypherbuffer, res);
    memcpy(&dest[res], tag, DET_AUTH_TAG_SIZE);

    free(cypherbuffer);
    free(tag);

    DEBUG_MSG("Inside deterministic authenticated encoding %d, returning size %d\n", size, size+DET_AUTH_PAD_SIZE);

    return res+DET_AUTH_PAD_SIZE;
}




int det_auth_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    DEBUG_MSG("Inside deterministic authenticated decryption %d\n", size);

    unsigned char* plaintext = malloc(sizeof(char)*size);
    unsigned char* tag = malloc(sizeof(char)*DET_AUTH_TAG_SIZE);
    int ciphertext_size = size - DET_AUTH_TAG_SIZE;

    memcpy(tag, &src[ciphertext_size], DET_AUTH_TAG_SIZE);

    int res = auth_decode(DET_AUTH_IV, plaintext, src, ciphertext_size, tag);

    if (res < 0) {
        DEBUG_MSG("Det_Auth_Decode = -1\n");
        return -1;
    }

    memcpy(dest, plaintext, res);

    free(plaintext);
    free(tag);

    DEBUG_MSG("Inside deterministic authenticate decryption %d, returning res %d\n", ciphertext_size, res);

    return res;
}

off_t det_auth_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi_in, struct fuse_operations nextlayer) {
    DEBUG_MSG("det_auth_get_file_size: %lu\n", origin_size);
    uint64_t nr_complete_blocks = origin_size / (DET_AUTH_BLOCKSIZE + DET_AUTH_PAD_SIZE);
    int last_incomplete_block_size = origin_size % (DET_AUTH_BLOCKSIZE + DET_AUTH_PAD_SIZE);
    uint64_t last_block_address = origin_size - last_incomplete_block_size;
    int last_block_real_size = 0;

    // We have original size but must get the real size of the last block which may be padded
    DEBUG_MSG("Got size %s original size is %lu last block size is %d\n", path, origin_size, last_incomplete_block_size);

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
                      origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

            // TODO: add -D_GNU_SOURCE for O_LARGEFILE
            fi->flags = O_RDONLY;
            res = nextlayer.open(path, fi);

            if (res == -1) {
                DEBUG_MSG("Failed open %s original size is %lu last block size is %d, last_block_address is %llu\n",
                          path, origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return res;
            }
        }

        DEBUG_MSG("read %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                  origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

        // read the block and decode to understand the number of bytes actually written
        res = nextlayer.read(path, aux_cyphered_buf, last_incomplete_block_size, last_block_address, fi);

        if (res < last_incomplete_block_size) {
            DEBUG_MSG("Failed read %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
                      origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
            return -1;
        }

        if (fi_in == NULL) {
            res = nextlayer.release(path, fi);

            if (res == -1) {
                DEBUG_MSG("Failed close %s original size is %lu last block size is %d, last_block_address is %llu\n",
                          path, origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);
                return -1;
            }
            free(fi);
        }

        DEBUG_MSG("Before decode read %s original size is %lu last block size is %d, last_block_address is %llu\n",
                  path, origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

        last_block_real_size = det_auth_decode(aux_plain_buf, (unsigned char*)aux_cyphered_buf, last_incomplete_block_size, NULL);

        DEBUG_MSG("After det_auth_decode block: %d\n", last_block_real_size);
    }

    DEBUG_MSG("size for file %s , last block real size is %d and file real size is %lu.\n", path, last_block_real_size,
              nr_complete_blocks * (DET_AUTH_BLOCKSIZE) + last_block_real_size);

    return nr_complete_blocks * DET_AUTH_BLOCKSIZE + last_block_real_size;
}

int det_auth_get_cyphered_block_size(int origin_size) {
    DEBUG_MSG("det_auth_get_cyphered_block_size: %d -- %d -- %d\n", origin_size, DET_AUTH_BLOCKSIZE, DET_AUTH_PAD_SIZE);
    int offset_block_aligned = origin_size;
    int chunks = (origin_size / DET_AUTH_BLOCKSIZE);
    if ((origin_size % DET_AUTH_BLOCKSIZE) != 0) {
        chunks++;
    }

    return offset_block_aligned + (DET_AUTH_PAD_SIZE*chunks);
}

uint64_t det_auth_get_cyphered_block_offset(uint64_t origin_offset) {
    DEBUG_MSG("DET_AUTH_BLOCKSIZE is  %d.\n", DET_AUTH_BLOCKSIZE);

    uint64_t blockid = origin_offset / DET_AUTH_BLOCKSIZE;

    return blockid * (DET_AUTH_BLOCKSIZE + DET_AUTH_PAD_SIZE);
}

off_t det_auth_get_truncate_size(off_t size) {
    uint64_t nr_blocks = size / DET_AUTH_BLOCKSIZE;
    uint64_t extra_bytes = size % DET_AUTH_BLOCKSIZE;

    off_t truncate_size = nr_blocks * (DET_AUTH_BLOCKSIZE + DET_AUTH_PAD_SIZE);

    if (extra_bytes > 0) {
        truncate_size += det_auth_get_cyphered_block_size(extra_bytes);
    }

    DEBUG_MSG("truncating file sfuse to #lu\n", truncate_size);
    return truncate_size;
}

int det_auth_clean() {
    return auth_clean();
}

//Batch processing methods
int det_auth_get_cycle_block_size(int origin_size, int is_last_cycle, int mode) {
    return auth_get_cycle_block_size(origin_size, is_last_cycle, mode, DET_AUTH_BLOCKSIZE, DET_AUTH_PAD_SIZE);
}

int det_auth_get_cycle_block_offset(int cycle) {
    return auth_get_cycle_block_offset(cycle, DET_AUTH_BLOCKSIZE, DET_AUTH_PAD_SIZE);
}

int det_auth_get_total_decoding_cycles(int size) {
    return auth_get_total_decoding_cycles(size, DET_AUTH_BLOCKSIZE, DET_AUTH_PAD_SIZE);
}

int det_auth_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle) {
    return auth_get_encrypted_chunk_size(encrypted_size, is_last_cycle, DET_AUTH_BLOCKSIZE, DET_AUTH_PAD_SIZE);
}

int det_auth_get_plaintext_block_offset(int cycle) {
    return auth_get_plaintext_block_offset(cycle, DET_AUTH_BLOCKSIZE);
}


// Supporting methods for convergent encryption -- TEMPORARY
void det_auth_set_key(unsigned char* key) {
    auth_set_key(key);
}

void det_auth_set_iv(unsigned char* iv) {
    DET_AUTH_IV = iv;
}

int det_auth_get_cyphered_chunk_size() {
    return DET_AUTH_BLOCKSIZE+DET_AUTH_PAD_SIZE;
}