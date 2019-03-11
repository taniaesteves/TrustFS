/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "remote.h"
#include "../../logging/timestamps/timestamps.h"


int remote_init_nfsfuse(char* nfsip, char* nfsfolder){

    char nfsflag[4]="-n";
    char mountflag[4]="-m";
    char pname[10]="fuse-nfs";


    char nfsaddress[200];
    
    strcpy(nfsaddress,"nfs://");
    strcat(nfsaddress, nfsip);
    strcat(nfsaddress, nfsfolder);
    strcat(nfsaddress, "?version=4");

    char* args[5];
    args[0]=pname;
    args[1]=nfsflag;
    args[2]=nfsaddress;
    args[3]=mountflag;
    args[4]="/";

    fusenfs_main(5, args);

    return 0;
}


int init_remote_layer(struct fuse_operations **originop, configuration data) {
    
    switch(data.remote_config.impl){
        case FUSENFS:
            remote_init_nfsfuse(data.remote_config.nfs_ip, data.remote_config.nfs_path);

            *originop=&nfs_oper;
        break;
        default:
            return -1;

    }

    return 0;
}

int clean_remote_layer(configuration data) {

    switch(data.remote_config.impl){
        case FUSENFS:
            fusenfs_clean();
        break;
        default:
            return -1;

    }

    return 0;
}
