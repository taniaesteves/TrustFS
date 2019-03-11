/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "compression.h"
#include "../../logging/timestamps/timestamps.h"
#include "drivers/compress_driver.h"

static struct compression_driver compress_driver;


int compress_init_fusecompress(char* root, char* compress_alg, int (*compressFunc)(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size), int (*decompressFunc)(uint8_t *dst, size_t *dst_size, uint8_t *src, size_t src_size, void *wrkmem, size_t wrkmem_size)) {

    char pname[13]="fusecompress";

    char* args[5];
    args[0]=pname;
    args[1]="-c";
    args[2]=compress_alg;
    args[3]=root;
    args[4]="/";

    main_compress(5, args, compressFunc, decompressFunc);
    return 0;
}


int init_compress_layer(struct fuse_operations **originop, configuration data) {
    
    if (data.compress_config.trusted == 0) {
        // compress_init();
        compress_driver.compress    = lzo1xCompress;
        compress_driver.decompress  = lzo1xDecompressSafe;
    } else {
        trusted_compress_init(data.compress_config.cipher_mode, data.compress_config.cipher_blocksize, data.compress_config.compress_blocksize);
        compress_driver.compress    = trustedLzo1xCompress;
        compress_driver.decompress  = trustedLzo1xDecompressSafe;
    }

    switch(data.compress_config.impl){
        case FCOMPRESS:
            compress_init_fusecompress(data.compress_config.path, data.compress_config.alg, compress_driver.compress, compress_driver.decompress);
            *originop=&fusecompress_oper;
        break;
        default:
            return -1;
    }

    return 0;
}

int clean_compress_layer(configuration data) {

    if (data.compress_config.trusted == 1)
        trusted_compress_clean();
        
    return 0;
}

