/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __COMPRESSIONFUSE_H__
#define __COMPRESSIONFUSE_H__

#ifdef __linux__
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif /* FUSE_USE_VERSION */
#endif /* __linux__ */

#if defined(_POSIX_C_SOURCE)
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
#endif

#include "../../layers_conf/layers_def.h"
#include "../../layers_conf/SFSConfig.h"
#include "../../logging/logdef.h"

#include "impls/fusecompress_layer/fusecompress.h"

#define FCOMPRESS 0

int init_compress_layer(struct fuse_operations** originop, configuration data);
int clean_compress_layer(configuration data);

#endif
