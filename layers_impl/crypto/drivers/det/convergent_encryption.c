/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "convergent_encryption.h"

int CONV_DIGEST_SIZE;
int CONV_OP_MODE;
int CONV_BLOCKSIZE;
int CONV_PAD_SIZE;
int CONV_FINAL_PAD_SIZE;

unsigned char* CONV_IV = NULL;
int CONV_IV_SIZE;

ivdb hashing_keys;
GMutex mutex_read;
GMutex mutex_write;

int get_digest_size() {
    switch (CONV_OP_MODE) {
        case sha1:
            return SHA_DIGEST_LENGTH;
        case sha256:
            return SHA256_DIGEST_LENGTH;
        case sha512:
            return SHA512_DIGEST_LENGTH;
        default:
            return -1;
    }
}

int calculate_hash(unsigned char* content, int content_size, unsigned char* digest, int digest_size) {
    int res = 0;

    SHA_CTX sha1_ctx;
    SHA256_CTX sha256_ctx;
    SHA512_CTX sha512_ctx;

    // DEBUG_MSG("Digest_size: %d -- %d\n", CONV_OP_MODE, CONV_DIGEST_SIZE);
    unsigned char* digest_tmp = malloc(sizeof(char)*CONV_DIGEST_SIZE);

    switch (CONV_OP_MODE) {
        case sha1:
            if (1 != SHA1_Init(&sha1_ctx)) openssl_handleErrors();

            if (1 != SHA1_Update(&sha1_ctx, content, content_size)) openssl_handleErrors();

            if (1 != SHA1_Final(digest_tmp, &sha1_ctx)) openssl_handleErrors();

            break;
        case sha256:
            if (1 != SHA256_Init(&sha256_ctx)) openssl_handleErrors();

            if (1 != SHA256_Update(&sha256_ctx, content, content_size)) openssl_handleErrors();

            if (1 != SHA256_Final(digest_tmp, &sha256_ctx)) openssl_handleErrors();

            break;
        case sha512:
            if (1 != SHA512_Init(&sha512_ctx)) openssl_handleErrors();

            if (1 != SHA512_Update(&sha512_ctx, content, content_size)) openssl_handleErrors();

            if (1 != SHA512_Final(digest_tmp, &sha512_ctx)) openssl_handleErrors();

            break;
        default:
            return -1;
    }

    memcpy(digest, digest_tmp, digest_size);
    free(digest_tmp);

    return res;
}

int conv_init(char* key, int key_size, unsigned char* arg_iv, int iv_size, int tag_size, int operation_mode, int block_size) {
    CONV_OP_MODE = operation_mode;
    CONV_DIGEST_SIZE = get_digest_size();

    CONV_BLOCKSIZE = block_size;
    CONV_PAD_SIZE = tag_size;
    CONV_IV = arg_iv;
    CONV_IV_SIZE = iv_size;
    CONV_FINAL_PAD_SIZE = tag_size + iv_size;

    init_hash(&hashing_keys);
    print_keys(&hashing_keys);

    g_mutex_init(&mutex_write);
    g_mutex_init(&mutex_read);

    DEBUG_MSG("Convergent Encryption Init: %d -- %d -- %d\n", CONV_DIGEST_SIZE, CONV_OP_MODE, CONV_BLOCKSIZE);
    return det_auth_init(key, key_size, arg_iv, iv_size, tag_size, GCM, block_size);
}

int conv_encode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    g_mutex_lock(&mutex_write);
    struct key_info* info = (struct key_info*) ident;
    unsigned char* cipherbuffer = malloc(sizeof(char)*(size+CONV_PAD_SIZE));

//    calculate content's hash -- cryptographic key
    unsigned char* hashed_key = malloc(sizeof(char)*CONV_DIGEST_SIZE);
    calculate_hash((unsigned char*) src, size, hashed_key, (CONV_DIGEST_SIZE));
    // DEBUG_MSG("Digest: <hash(msg)> = %s\n", hashed_key);

//------------------------------------------------------------------------------------------------------------------------

//    calculate path and offset hash
    char offset_str[21];
    sprintf(offset_str, "%lu", info->offset);
    char* unhashed_row = concat(info->path, offset_str);

    DEBUG_MSG("Going to generate hash row for file %s at offset %d -- %s - %d\n", info->path, info->offset, unhashed_row, size);

//    store cryptographic key in value_db
    value_db* value = malloc(sizeof(value_db));
    value->hashed_key = malloc(sizeof(char)*(CONV_DIGEST_SIZE));
    memcpy(value->hashed_key, hashed_key, CONV_DIGEST_SIZE);

//    store KV-pair in KV-Store
    hash_put(&hashing_keys, unhashed_row, value);
//    print_keys(&hashing_keys);

//------------------------------------------------------------------------------------------------------------------------

//    Check if the KV-pair is stored

//    DEBUG_MSG("contains (encode) -- %d\n", hash_contains_key(&hashing_keys, unhashed_row));
//    value_db* value_tmp = malloc(sizeof(value_db));
//    value_tmp->hashed_key = malloc(sizeof(char)*CONV_DIGEST_SIZE);
//    hash_get(&hashing_keys, unhashed_row, &value_tmp);
//    DEBUG_MSG("KV-Pair: %s - %s\n", unhashed_row, value_tmp->hashed_key);

//------------------------------------------------------------------------------------------------------------------------

//    Encode with content's hash as key
//    this set_key is temporary: if we consider a multi-threaded scenario, this will not work, since
//    two concurrent clients will try to set the key and the data could be corrupted. The solution is
//    to pass the key as a parameter to the encode/decode function

//    Set cryptographic key for current content
    det_auth_set_key(hashed_key);
//    Set initialization vector -- Temporary
    det_auth_set_iv(CONV_IV);

//    Encode with deterministic authenticated encryption
    int res = det_auth_encode(cipherbuffer, src, size, ident);

    if (res < 0) {
        return -1;
    }

    memcpy(dest, cipherbuffer, res);
    memcpy(&dest[res], CONV_IV, CONV_IV_SIZE);

//    free pointers
    free(cipherbuffer);
    free(hashed_key);

    g_mutex_unlock(&mutex_write);

    return res + CONV_IV_SIZE;
}

int conv_decode(unsigned char* dest, const unsigned char* src, int size, void* ident) {
    g_mutex_lock(&mutex_read);
    struct key_info* info = (struct key_info*) ident;

//    calculate path and offset hash
    char offset_str[21];
    sprintf(offset_str, "%lu", info->offset);
    char* row = concat(info->path, offset_str);

    DEBUG_MSG("Going to generate hash row (decode) for file %s at offset %d -- %s - %d\n", info->path, info->offset, row, size);

//    Check if KV-Pair is in hash
//    print_keys(&hashing_keys);
    int contains = hash_contains_key(&hashing_keys, row);
    // DEBUG_MSG("contains (decode) -- %d\n", contains);

//    get KV-pair in KV-Store
    value_db* val = malloc(sizeof(value_db));
    if (contains > 0) {
        val->hashed_key = malloc(sizeof(char)*CONV_DIGEST_SIZE);
        hash_get(&hashing_keys, row, &val);
//        DEBUG_MSG("KV-Pair: %s - %s\n", row, val->hashed_key);
    } else {
        DEBUG_MSG("Hash does not contains key %s\n", row);
        return -1;
    }

//------------------------------------------------------------------------------------------------------------------------

//    Decode with content's hash
//  Set cryptographic key for current content
    det_auth_set_key(val->hashed_key);

//    Extract initialization vector from message
    unsigned char iv_tmp[CONV_IV_SIZE];
    memcpy(&iv_tmp, &src[size-CONV_IV_SIZE], CONV_IV_SIZE);

//    Set initialization vector -- Temporary
    det_auth_set_iv(iv_tmp);

    int res = det_auth_decode(dest, src, size-CONV_IV_SIZE, ident);

    if (res < 0) {
        print_keys(&hashing_keys);
        DEBUG_MSG("CONV_ERROR: contains = %d; tried to read key = %s\n", contains, row);
        DEBUG_MSG("CONV_ERROR: -1; path - %s ; offset - %lu ;\n", info->path, info->offset);
        return -1;
    }

//    free pointers
    free(row);

    g_mutex_unlock(&mutex_read);
    return res;
}

off_t conv_get_file_size(const char* path, off_t origin_size, struct fuse_file_info* fi_in, struct fuse_operations nextlayer) {    
    uint64_t nr_complete_blocks = origin_size / (CONV_BLOCKSIZE + CONV_FINAL_PAD_SIZE);
    int last_incomplete_block_size = origin_size % (CONV_BLOCKSIZE + CONV_FINAL_PAD_SIZE);
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

            // DEBUG_MSG("before open %s original size is %lu last block size is %d, last_block_address is %llu\n", path,
            //           origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

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

        // DEBUG_MSG("Before decode read %s original size is %lu last block size is %d, last_block_address is %llu\n",
        //           path, origin_size, last_incomplete_block_size, (unsigned long long int)last_block_address);

        struct key_info* info = malloc(sizeof(struct key_info));
        info->path = malloc(sizeof(char)*(strlen(path)+1));
        memcpy((char*) info->path, path, strlen(path)+1);
        info->offset = last_block_address;

        last_block_real_size = conv_decode(aux_plain_buf, (unsigned char*)aux_cyphered_buf, last_incomplete_block_size, info);        
    }

    DEBUG_MSG("size for file %s , last block real size is %d and file real size is %lu.\n", path, last_block_real_size,
              nr_complete_blocks * (CONV_BLOCKSIZE) + last_block_real_size);

    return nr_complete_blocks * CONV_BLOCKSIZE + last_block_real_size;
}

int conv_get_cyphered_block_size(int origin_size) {
    int offset_block_aligned = origin_size;
    int chunks = (origin_size / CONV_BLOCKSIZE);
    if ((origin_size % CONV_BLOCKSIZE) != 0) {
        chunks++;
    }

    return offset_block_aligned + (CONV_FINAL_PAD_SIZE*chunks);
}

uint64_t conv_get_cyphered_block_offset(uint64_t origin_offset) {
    uint64_t blockid = origin_offset / CONV_BLOCKSIZE;

    return blockid * (CONV_BLOCKSIZE + CONV_FINAL_PAD_SIZE);
}

off_t conv_get_truncate_size(off_t size) {
    uint64_t nr_blocks = size / CONV_BLOCKSIZE;
    uint64_t extra_bytes = size % CONV_BLOCKSIZE;

    off_t truncate_size = nr_blocks * (CONV_BLOCKSIZE + CONV_FINAL_PAD_SIZE);

    if (extra_bytes > 0) {
        truncate_size += conv_get_cyphered_block_size(extra_bytes);
    }

    // DEBUG_MSG("truncating file sfuse to #lu\n", truncate_size);
    return truncate_size;

}

int conv_clean() {
//    TODO free mutex
//    TODO clean/free hash
    return det_auth_clean();
}

//Batch processing methods
int conv_get_cycle_block_size(int origin_size, int is_last_cycle, int mode) {
    return auth_get_cycle_block_size(origin_size, is_last_cycle, mode, CONV_BLOCKSIZE, CONV_FINAL_PAD_SIZE);
}

int conv_get_cycle_block_offset(int cycle) {
    return auth_get_cycle_block_offset(cycle, CONV_BLOCKSIZE, CONV_FINAL_PAD_SIZE);
}

int conv_get_total_decoding_cycles(int size) {
    return auth_get_total_decoding_cycles(size, CONV_BLOCKSIZE, CONV_FINAL_PAD_SIZE);
}

int conv_get_encrypted_chunk_size(int encrypted_size, int is_last_cycle) {
    return auth_get_encrypted_chunk_size(encrypted_size, is_last_cycle, CONV_BLOCKSIZE, CONV_FINAL_PAD_SIZE);
}

int conv_get_plaintext_block_offset(int cycle) {
    return det_auth_get_plaintext_block_offset(cycle);
}

int conv_get_cyphered_chunk_size() {
    return CONV_BLOCKSIZE + CONV_FINAL_PAD_SIZE;
}


