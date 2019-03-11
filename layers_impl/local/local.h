/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __LOCAL_H__
#define __LOCAL_H__

#define FUSE_USE_VERSION 26

#define _GNU_SOURCE

#include <fuse.h>
#include "../../logging/logdef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include "../../utils/utils.h"
#include "../../layers_conf/SFSConfig.h"
#include "../../layers_conf/layers_def.h"


int init_local_layer(struct fuse_operations **fuse_operations, configuration data);
int clean_local_layer(configuration data);

#endif
