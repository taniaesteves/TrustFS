/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __MAP_H__
#define __MAP_H__

#include "../../logging/logdef.h"
#include <stdlib.h>
#include <glib.h>
//#include <glib-2.0/glib.h>1
#include <stdint.h>
#include <stdio.h>
#include "../utils.h"

typedef struct db_struct { GHashTable* hash; } ivdb;

typedef struct value {
    uint64_t file_size;
    unsigned char* hashed_key;
} value_db;

char* get_unique_ident(int offset, const char* path);

int init_hash(ivdb* db);

int hash_put(ivdb* db, char* key, value_db* value);

int hash_get(ivdb* db, char* key, value_db** value);

// Copy every key with key "from" to a new key with "to";
void hash_rename(ivdb* db, char* from, char* to);

int hash_contains_key(ivdb* db, char* key);

int clean_hash(ivdb* db, char* path);

void print_keys(struct db_struct* st);

void remove_keys(ivdb* st, char* key);

void move_key(ivdb* st, char* from, char* to);

#endif
