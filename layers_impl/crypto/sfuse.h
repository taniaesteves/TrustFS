/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __SFUSE_H__
#define __SFUSE_H__

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

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/param.h>
#include "../../layers_conf/layers_def.h"
#include "drivers/nopcrypt.h"
#include "drivers/nopcrypt_padded.h"
#include "../../layers_conf/SFSConfig.h"
#include "drivers/rand/rand_symmetric.h"
#include "drivers/det/det_symmetric.h"
#include "drivers/nopcrypt.h"
#include "drivers/openssl/auth_encryption.h"
#include "drivers/rand/rand_authenticated.h"
#include "drivers/det/det_authenticated.h"
#include "drivers/det/convergent_encryption.h"
#include "drivers/trusted_crypt.h"
#include "../../utils/map/map.h"

#include "../../logging/logdef.h"

#define NOPCRYPT 0
#define NOPCRYPT_PAD 1
#define STANDARD 2
#define DETERMINISTIC 3
#define AUTH_RAND 4
#define AUTH_DET 5
#define CONVERGENT 6
#define TRUSTED_AUTH_RAND 7
#define TRUSTED_DET_SYMMETRIC 8


int init_sfuse_driver(struct fuse_operations** originop, configuration data);
int clean_sfuse_driver(configuration data);

#endif /* __SFUSE_H__ */
