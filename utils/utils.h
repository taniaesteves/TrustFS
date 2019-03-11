/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/



#ifndef __SDS_UTILS_H__
#define __SDS_UTILS_H__

#define PATHSIZE 500
// char ROOTPATH[PATHSIZE];

#include <errno.h>
#include <linux/limits.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>


/**
 * Checks if a file exists. Returns 1 if it exists, 0 if it does not
 * @param path The path to the file to check
 * @return 1 if the path leads to a regular file, 0 otherwise
 */
int file_exists(char *path);

int replace_path(char const *path, const char *newpath);

void generate_random_block(unsigned char *str, int size);

void str_split(char *a_str);

/**
 * Checks if a directory exists and if it does not create it.
 * @param path Path to the directory
 * @return 0 if the already directory exists or has been created, -1 otherwise
 */
int mkdir_p(const char *path);

void openssl_handleErrors(void);

char* concat(const char* s1, const char* s2);

int isSpecialPath(const char *path);

#endif /* __SDS_UTILS_H__ */
