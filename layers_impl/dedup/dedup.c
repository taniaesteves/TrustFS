/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "dedup.h"
#include "../../logging/timestamps/timestamps.h"


int dedup_init_mkddumbfs(char* psize, char* bsize, char* hash, char* root, char* source_path){
    char command[500];

    strcpy(command, source_path);
    strcat(command, "/layers_impl/dedup/impls/ddumbfs_layer/src/mkddumbfs -B ");
    strcat(command, bsize);
    strcat(command, " -s ");
    strcat(command, psize);
    strcat(command, " -H ");
    strcat(command, hash);
    strcat(command, " ");
    strcat(command, root);
    printf("Command is %s\n", command);

    system(command);
    return 0;
}

int dedup_init_ddumbfs(char* root) {

    char parentflag[4]="-o";
    char pname[10]="ddumbfs";
    char pool[10]="pool=0";

    char* args[6];
    args[0]=pname;
    args[1]=parentflag;
    args[2]=root;
    args[3]="/";
    args[4]=parentflag;
    args[5]=pool;

    main_ddfs(6, args);
    return 0;
}



int dedup_init_mklessfs(char* conf_path, char* source_path){
    char command[300];
    strcpy(command, source_path);
    strcat(command, "/layers_impl/dedup/impls/lessfs_layer/mklessfs -f -c ");
    strcat(command, conf_path);
    // printf("Command is %s\n", command);

    system(command);
    return 0;
}

int dedup_init_lessfs(char* conf_path) {


    char pname[10]="lessfs";

    char* args[3];
    args[0]=pname;
    args[1]=conf_path;
    args[2]="/";

    lessfs_main(3, args);
    return 0;
}

int init_dedup_layer(struct fuse_operations **originop, configuration data) {

    char fuserootpath[100];

    switch(data.dedup_config.impl){
        case DDUMBFS:
            strcpy(fuserootpath, "parent=");
            strcat(fuserootpath, data.dedup_config.root_path);

            if (data.dedup_config.format == 1)
                dedup_init_mkddumbfs(data.dedup_config.partition_size,data.dedup_config.block_size, data.dedup_config.hash,data.dedup_config.root_path,data.dedup_config.source_path);
            dedup_init_ddumbfs(fuserootpath);

            *originop=&ddumb_ops;
        break;
        case LESSFS:

            if (data.dedup_config.format == 1)
                dedup_init_mklessfs(data.dedup_config.conf_path,data.dedup_config.source_path);
            dedup_init_lessfs(data.dedup_config.conf_path);

            *originop=&lessfs_oper;
        break;
        default:
            return -1;
    }

    return 0;
}

int clean_dedup_layer(configuration data) {
        

    return 0;
}