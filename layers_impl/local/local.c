/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. Its performance is terrible.
 *
 * Compile with
 *
 *     gcc -Wall passthrough.c `pkg-config fuse3 --cflags --libs` -o passthrough
 *
 * ## Source code ##
 * \include passthrough.c
 */

#include <assert.h>

#include "local.h"
#include "../../logging/timestamps/timestamps.h"

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

char rootpath[PATHSIZE];

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;

    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = lstat(newpath, stbuf);
    DEBUG_MSG("getattr size %lu\n", stbuf->st_size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_fgetattr(const char *path, struct stat *stbuf,
                  struct fuse_file_info *fi)
{
    int res;

    res = fstat(fi->fh, stbuf);
    DEBUG_MSG("fgetattr size %lu\n", stbuf->st_size);
#if FUSE_VERSION >= 29
    // Fall back to global I/O size. See loopback_getattr().
    stbuf->st_blksize = 0;
#endif

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
xmp_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    res = close(dup(fi->fh));
    if (res == -1) {
        return -errno;
    }

    return 0;
}




static int xmp_access(const char *path, int mask)
{
    int res;

    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = access(newpath, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;

    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = readlink(newpath, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}



static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(newpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(newpath, mode);
    else
        res = mknod(newpath, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;

    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = mkdir(newpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = unlink(newpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = rmdir(newpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;
    char newpathfrom[PATHSIZE];
    strcpy(newpathfrom, rootpath);
    strcat(newpathfrom, from);

    char newpathto[PATHSIZE];
    strcpy(newpathto, rootpath);
    strcat(newpathto, to);


    res = symlink(newpathfrom, newpathto);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;

    char newpathfrom[PATHSIZE];
    strcpy(newpathfrom, rootpath);
    strcat(newpathfrom, from);

    char newpathto[PATHSIZE];
    strcpy(newpathto, rootpath);
    strcat(newpathto, to);

    res = rename(newpathfrom, newpathto);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;
    char newpathfrom[PATHSIZE];
    strcpy(newpathfrom, rootpath);
    strcat(newpathfrom, from);

    char newpathto[PATHSIZE];
    strcpy(newpathto, rootpath);
    strcat(newpathto, to);


    res = link(newpathfrom, newpathto);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;
   char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = chmod(newpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);
    
    res = lchown(newpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    if (fi != NULL)
        res = ftruncate(fi->fh, size);
    else
        res = truncate(newpath, size);
    if (res == -1)
        return -errno;

    return 0;

}

static int xmp_truncate(const char *path, off_t size)
{
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = truncate(newpath, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_utime(const char *path, struct utimbuf *buf)
{
    int res;

    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = utime(newpath, buf);
    if(res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2],
               struct fuse_file_info *fi)
{
    (void) fi;
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    /* don't use utime/utimes since they follow symlinks */
    res = utimensat(0, newpath, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int xmp_create(const char *path, mode_t mode,
              struct fuse_file_info *fi)
{
    int res;
   char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);
    res = open(newpath, fi->flags, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    res = open(newpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    int fd;
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    if(fi == NULL)
        fd = open(newpath, O_RDONLY);
    else
        fd = fi->fh;
    
    if (fd == -1)
        return -errno;

    DEBUG_MSG("Going to read offset %ld with size %lu\n", offset, size);

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    if(fi == NULL)
        close(fd);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    (void) fi;
    if(fi == NULL)
        fd = open(newpath, O_WRONLY);
    else
        fd = fi->fh;
    
    if (fd == -1)
        return -errno;

    DEBUG_MSG("Going to write offset %ld with size %lu\n", offset, size);
    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    if(fi == NULL)
        close(fd);
    return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);
    res = statvfs(newpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    char newpath[PATHSIZE];
    replace_path(rootpath, newpath);
    replace_path(path, newpath);
    close(fi->fh);
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    
    fsync(fi->fh);
    return 0;
}

struct xmp_dirp {
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

static int
xmp_opendir(const char *path, struct fuse_file_info *fi)
{
    int res;
    char newpath[PATHSIZE];
    strcpy(newpath, rootpath);
    strcat(newpath, path);

    struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
    if (d == NULL) {
        return -ENOMEM;
    }

    d->dp = opendir(newpath);
    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
    }

    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long)d;

    return 0;
}

static inline struct xmp_dirp *
get_dirp(struct fuse_file_info *fi)
{
    return (struct xmp_dirp *)(uintptr_t)fi->fh;
}

static int
xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);
    
    (void)path;

    if (offset != d->offset) {
        seekdir(d->dp, offset);
        d->entry = NULL;
        d->offset = offset;
    }

    while (1) {
        struct stat st;
        off_t nextoff;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry) {
                break;
            }
        }

        memset(&st, 0, sizeof(st));
        st.st_ino = d->entry->d_ino;
        st.st_mode = d->entry->d_type << 12;
        nextoff = telldir(d->dp);
        if (filler(buf, d->entry->d_name, &st, nextoff)) {
            break;
        }

        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

static int
xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);

    (void)path;

    closedir(d->dp);
    free(d);

    return 0;
}


static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .fgetattr   = xmp_fgetattr,
    .opendir    = xmp_opendir,
    .flush      = xmp_flush,
    .ftruncate  = xmp_ftruncate,
    .access     = xmp_access,
    .readlink   = xmp_readlink,
    .releasedir = xmp_releasedir,
    .readdir    = xmp_readdir,
    .mknod      = xmp_mknod,
    .mkdir      = xmp_mkdir,
    .symlink    = xmp_symlink,
    .unlink     = xmp_unlink,
    .rmdir      = xmp_rmdir,
    .rename     = xmp_rename,
    .link       = xmp_link,
    .chmod      = xmp_chmod,
    .chown      = xmp_chown,
    .truncate   = xmp_truncate,
    .utime      = xmp_utime,
#ifdef HAVE_UTIMENSAT
    .utimens    = xmp_utimens,
#endif
    .open       = xmp_open,
    .create     = xmp_create,
    .read       = xmp_read,
    .write      = xmp_write,
    .statfs     = xmp_statfs,
    .release    = xmp_release,
    .fsync      = xmp_fsync,
#ifdef HAVE_SETXATTR
    .setxattr   = xmp_setxattr,
    .getxattr   = xmp_getxattr,
    .listxattr  = xmp_listxattr,
    .removexattr    = xmp_removexattr,
#endif
};

 
int init_local_layer(struct fuse_operations **fuse_operations, configuration data) {
   
    strcpy(rootpath,data.local_config.path);

    *fuse_operations = &xmp_oper;
    DEBUG_MSG("Going to return setup driver");
    return 0;
}

int clean_local_layer(configuration data) {
    return 0;
}
