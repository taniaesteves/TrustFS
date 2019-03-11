/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __NOPALIGN_H__
#define __NOPALIGN_H__

#include "../../../layers_conf/layers_def.h"
#include "../../../logging/logdef.h"
#include <string.h>
#include <stdint.h>
#include <fuse.h>
#include <stdio.h>

int nop_align_read(const char *path, char *buf, size_t size, off_t offset, void *fi, struct fuse_operations nextlayer);
int nop_align_write(const char *path, const char *buf, size_t size, off_t offset, void *fi,
                    struct fuse_operations nextlayer);
int nop_align_create(const char *path, mode_t mode, void *fi, struct fuse_operations nextlayer);
int nop_align_open(const char *path, void *fi, struct fuse_operations nextlayer);
int nop_align_truncate(const char *path, off_t size, struct fuse_file_info *fi, struct fuse_operations nextlayer);

#endif /* __NOPALIGN_H__ */
