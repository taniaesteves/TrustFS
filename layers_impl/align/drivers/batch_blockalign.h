/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __BATCH_BLOCKALIGN_H__
#define __BATCH_BLOCKALIGN_H__

#include "../../../layers_conf/layers_def.h"
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../../logging/logdef.h"
#include "../../../layers_conf/SFSConfig.h"
#include "../../../utils/map/map.h"

#define READ 0
#define WRITE 1

int batch_block_align_read(const char *path, char *buf, size_t size, off_t offset, void *fi, struct fuse_operations);
int batch_block_align_write(const char *path, const char *buf, size_t size, off_t offset, void *fi, struct fuse_operations);
int batch_block_align_create(const char *path, mode_t mode, void *fi, struct fuse_operations nextlayer);
int batch_block_align_open(const char *path, void *fi, struct fuse_operations nextlayer);
int batch_block_align_truncate(const char *path, off_t size, struct fuse_file_info *fi, struct fuse_operations nextlayer);

struct batch_io_info {
    const char *path;
    void *fi;
    struct fuse_operations nextlayer;
};

void define_batch_block_size(block_align_config config);

#endif /* __BLOCKALIGN_H__ */
