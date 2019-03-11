/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

/*
 * Alignment layer for fuse filesystems.
 * This layer can be combined with the Sfuse layer to align blocks prior to encoding/decoding data
 */

#include "alignfuse.h"
#include "../../logging/timestamps/timestamps.h"

// struct with original operations from mounted filesystem
static struct fuse_operations *originalfs_oper;

// struct with alignfuse operations
static struct fuse_operations alignfuse_oper;

// struct with align algorithms
static struct align_driver align_driver;

// GSList *align_write_list = NULL, *align_read_list = NULL;

static int alignfuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // struct timeval tstop, tstart;
    // gettimeofday(&tstart, NULL);

    if (isSpecialPath(path) == 1)        
        return originalfs_oper->read(path, buf, size, offset, fi);

    // DEBUG_MSG("alignfuse_read: Going to read offset %ld with size %lu\n", offset, size);
    int res = align_driver.align_read(path, buf, size, offset, (void *)fi, *originalfs_oper);        
    // DEBUG_MSG("alignfuse_read: Exiting function alignfuse_read offset %ld size %ld. res is %d\n", offset, size, res);

    // gettimeofday(&tstop, NULL);
    // store(&align_read_list, tstart, tstop);

    return res;
}

static int alignfuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // struct timeval tstop, tstart;
    // gettimeofday(&tstart, NULL);
    
    if (isSpecialPath(path) == 1)
        return originalfs_oper->write(path, buf, size, offset, fi);

    // DEBUG_MSG("alignfuse_write: Going to write path %s offset %ld with size %lu\n", path, offset, size);        
    int res = align_driver.align_write(path, buf, size, offset, (void *)fi, *originalfs_oper);
    // DEBUG_MSG("alignfuse_write: Exiting function alignfuse_write path %s offset %ld with size %lu with res = %ld\n", path, offset, size, res);        

    // gettimeofday(&tstop, NULL);
    // store(&align_write_list, tstart, tstop);

    return res;
}

static int alignfuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    if (isSpecialPath(path) == 1)
        return originalfs_oper->create(path, mode, fi);
    
    // DEBUG_MSG("alignfuse_create: Alignfuse create path %s\n", path);
    int res = align_driver.align_create(path, mode, (void *)fi, *originalfs_oper);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int alignfuse_open(const char *path, struct fuse_file_info *fi) {
    if (isSpecialPath(path) == 1)
        return originalfs_oper->open(path, fi);
    
    // DEBUG_MSG("alignfuse_open: Align fuse open path %s\n", path);
    int res = align_driver.align_open(path, (void *)fi, *originalfs_oper);
    if (res == -1) {
        return -errno;
    }
    return 0;

}

static int alignfuse_truncate(const char *path, off_t size) {
    if (isSpecialPath(path) == 1)
        return originalfs_oper->truncate(path, size);
    
    // DEBUG_MSG("alignfuse_truncate: align truncate path %s %lu\n", path, size);
    int res;
    // This function re-reads any blocks if necessary and truncates them
    res = align_driver.align_truncate(path, size, NULL, *originalfs_oper);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int alignfuse_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
    if (isSpecialPath(path) == 1)
        return originalfs_oper->ftruncate(path, size, fi);

    // DEBUG_MSG("alignfuse_ftruncate: align ftruncate path %s %lu\n", path, size);
    int res;
    res = align_driver.align_truncate(path, size, fi, *originalfs_oper);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

int init_align_driver(struct fuse_operations **fuse_operations, configuration config) {
    DEBUG_MSG("Going to init align_driver\n");

    // this is received from sfuse
    originalfs_oper = *fuse_operations;

    // TODO:
    // Maybe this could be initialized with the alignfuse_oper struct
    alignfuse_oper.init = originalfs_oper->init;
    alignfuse_oper.destroy = originalfs_oper->destroy;
    alignfuse_oper.getattr = originalfs_oper->getattr;
    alignfuse_oper.fgetattr = originalfs_oper->fgetattr;
    alignfuse_oper.access = originalfs_oper->access;
    alignfuse_oper.readlink = originalfs_oper->readlink;
    alignfuse_oper.opendir = originalfs_oper->opendir;
    alignfuse_oper.readdir = originalfs_oper->readdir;
    alignfuse_oper.releasedir = originalfs_oper->releasedir;
    alignfuse_oper.mknod = originalfs_oper->mknod;
    alignfuse_oper.mkdir = originalfs_oper->mkdir;
    alignfuse_oper.symlink = originalfs_oper->symlink;
    alignfuse_oper.unlink = originalfs_oper->unlink;
    alignfuse_oper.rmdir = originalfs_oper->rmdir;
    alignfuse_oper.rename = originalfs_oper->rename;
    alignfuse_oper.link = originalfs_oper->link;
    alignfuse_oper.create = alignfuse_create;
    alignfuse_oper.open = alignfuse_open;
    alignfuse_oper.read = alignfuse_read;
    alignfuse_oper.write = alignfuse_write;
    alignfuse_oper.statfs = originalfs_oper->statfs;
    alignfuse_oper.flush = originalfs_oper->flush;
    alignfuse_oper.release = originalfs_oper->release;
    alignfuse_oper.fsync = originalfs_oper->fsync;
    alignfuse_oper.truncate = alignfuse_truncate;
    alignfuse_oper.ftruncate = alignfuse_ftruncate;
    alignfuse_oper.chown = originalfs_oper->chown;
    alignfuse_oper.chmod = originalfs_oper->chmod;
    alignfuse_oper.utimens = originalfs_oper->utimens;
    alignfuse_oper.utime = originalfs_oper->utime;
    alignfuse_oper.setxattr    = originalfs_oper->setxattr;
    alignfuse_oper.getxattr    = originalfs_oper->getxattr;
    alignfuse_oper.listxattr   = originalfs_oper->listxattr;
    alignfuse_oper.removexattr = originalfs_oper->removexattr;

    switch (config.block_config.mode) {
        case NOP:
            align_driver.align_write = nop_align_write;
            align_driver.align_read = nop_align_read;
            align_driver.align_create = nop_align_create;
            align_driver.align_open = nop_align_open;
            align_driver.align_truncate = nop_align_truncate;
            break;
        case BLOCK:
            align_driver.align_read = block_align_read;
            align_driver.align_write = block_align_write;
            align_driver.align_create = block_align_create;
            align_driver.align_open = block_align_open;
            align_driver.align_truncate = block_align_truncate;
            define_block_size(config.block_config);
            break;
        case BATCH_BLOCK:
            align_driver.align_read = batch_block_align_read;
            align_driver.align_write = batch_block_align_write;
            align_driver.align_create = batch_block_align_create;
            align_driver.align_open = batch_block_align_open;
            align_driver.align_truncate = batch_block_align_truncate;
            define_batch_block_size(config.block_config);
            break;
        default:
            exit(-1);
    }

    *fuse_operations = &alignfuse_oper;

    return 0;
}

int clean_align_driver(configuration config) {
    // DEBUG_MSG("Going to clean multi_loopback drivers\n");
    // print_latencies(align_write_list, "align", "write");
    // print_latencies(align_read_list, "align", "read");
    return 0;
}
