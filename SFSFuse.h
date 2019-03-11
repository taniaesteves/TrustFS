/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __SFSFuse_H__
#define __SFSFuse_H__

#include "layers_impl/align/alignfuse.h"
#include "layers_impl/crypto/sfuse.h"
#include "layers_impl/dedup/dedup.h"
#include "layers_impl/compression/compression.h"
#include "inih/ini.h"
#include "logging/logdef.h"
#include "layers_conf/SFSConfig.h"
#include "layers_impl/loopback/multi_loopback.h"
#include "layers_impl/nop/nopfuse.h"
#include "layers_impl/remote/remote.h"
#include "layers_impl/local/local.h"
#include <stdio.h>
#include <fuse.h>

#endif /* __SFSFuse_H__ */
