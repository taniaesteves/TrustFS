/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "SFSConfig.h"

int handle_section_layers(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "block_align") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(BLOCK_ALIGN));
    } else if (strcmp(name, "sfuse") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(SFUSE));
    } else if (strcmp(name, "multi_loop") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(MULTI_LOOPBACK));
    } else if (strcmp(name, "nopfuse") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(NOPFUSE));
    } else if (strcmp(name, "dedup") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(DEDUPFUSE));
    } else if (strcmp(name, "compress") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(COMPRESSFUSE));
    } else if (strcmp(name, "remote") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(REMOTEFUSE));
    } else if (strcmp(name, "local") == 0) {
        config->layers = g_slist_append(config->layers, GINT_TO_POINTER(LOCALFUSE));
    }else {
        return 0;
    }
    return 1;
}

int handle_section_block_align(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "block_size") == 0) {
        (config->block_config).block_size = atoi(value);
    } else if (strcmp(name, "mode") == 0) {
        (config->block_config).mode = atoi(value);
    } else {
        return 0;
    }

    return 1;
}

//TODO: add cipher mode
int handle_section_sfuse(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "block_size") == 0) {
        (config->enc_config).block_size = atoi(value);
    } else if (strcmp(name, "align_mode") == 0) {
        (config->enc_config).align_mode = atoi(value);
    } else if (strcmp(name, "key") == 0) {
        (config->enc_config).key = strdup(value);
    } else if (strcmp(name, "iv") == 0) {
        (config->enc_config).iv = strdup(value);
    } else if (strcmp(name, "key_size") == 0) {
        (config->enc_config).key_size = atoi(value);
    } else if (strcmp(name, "iv_size") == 0) {
        (config->enc_config).iv_size = atoi(value);
    } else if (strcmp(name, "mode") == 0) {
        (config->enc_config).mode = atoi(value);
    } else if (strcmp(name, "operation_mode") == 0) {
        (config->enc_config).operation_mode = atoi(value);
    } else if (strcmp(name, "cache") == 0) {
        (config->enc_config).cache = atoi(value);
    } else {
        return 0;
    }

    return 1;
}

int handle_section_multi_loop(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "mode") == 0) {
        (config->m_loop_config).mode = atoi(value);
    } else if (strcmp(name, "ndevs") == 0) {
        (config->m_loop_config).ndevs = atoi(value);

    } else if (strstr(name, "path") != NULL) {
        // TODO: FREE these strings
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);

        (config->m_loop_config).loop_paths = g_slist_append((config->m_loop_config).loop_paths, alloc_val);
    } else if (strcmp(name, "root") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->m_loop_config).root_path = alloc_val;
    } else {
        return 0;
    }

    return 1;
}

int handle_section_local(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->local_config).path = alloc_val;
    } else {
        return 0;
    }

    return 1;
}


int handle_section_compress(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->compress_config).path = alloc_val;
    } else if (strcmp(name, "impl") == 0) {
        (config->compress_config).impl = atoi(value);
    } else if (strcmp(name, "cipher_mode") == 0) {
        (config->compress_config).cipher_mode = atoi(value);
    } else if (strcmp(name, "cipher_blocksize") == 0) {
        (config->compress_config).cipher_blocksize = atoi(value);
    } else if (strcmp(name, "compress_blocksize") == 0) {
        (config->compress_config).compress_blocksize = atoi(value);
    } else if (strcmp(name, "trusted") == 0) {
        (config->compress_config).trusted = atoi(value);
    } else if (strcmp(name, "alg") == 0) {
        int alg_size = strlen(value);
        char* alloc_val = malloc(alg_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->compress_config).alg = alloc_val;
    } else {
        return 0;
    }

    return 1;
}

int handle_section_dedup(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "impl") == 0) {
        (config->dedup_config).impl = atoi(value);
    }
    else if (strcmp(name, "hash") == 0) {        
        int hash_size = strlen(value);
        char* alloc_val = malloc(hash_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).hash = alloc_val;
    }
    else if (strcmp(name, "format") == 0) {
        (config->dedup_config).format = atoi(value);
    }
    else if (strcmp(name, "trusted") == 0) {
        (config->dedup_config).trusted = atoi(value);
    }
    else if (strcmp(name, "epoch_ops") == 0) {
        (config->dedup_config).epoch_ops = atoi(value);
    }
    else if (strcmp(name, "block_size") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).block_size = alloc_val;
    }
    else if (strcmp(name, "partition_size") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).partition_size = alloc_val;
    }
    else if (strcmp(name, "root_path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).root_path = alloc_val;
    }
    /*else if (strcmp(name, "mount_path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).mount_path = alloc_val;
    }*/
    else if (strcmp(name, "source_path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).source_path = alloc_val;

    } else if (strcmp(name, "conf_path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->dedup_config).conf_path = alloc_val;
    }
    else {
        return 0;
    }
    return 1;
}


int handle_section_remote(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "impl") == 0) {
        (config->remote_config).impl = atoi(value);
    }
    else if (strcmp(name, "driver") == 0) {
        (config->remote_config).driver = atoi(value);
    }
    /*else if (strcmp(name, "mount_path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->remote_config).mount_path = alloc_val;
    }*/
    else if (strcmp(name, "nfs_ip") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->remote_config).nfs_ip = alloc_val;
    } else if (strcmp(name, "nfs_path") == 0) {
        int path_size = strlen(value);
        char* alloc_val = malloc(path_size * sizeof(char*) + 1);
        strcpy(alloc_val, (char*)value);
        (config->remote_config).nfs_path= alloc_val;
    }
    else {
        return 0;
    }
    return 1;
}

int handle_section_log(configuration* config, const char* name, const char* value) {
    if (strcmp(name, "mode") == 0) {
        config->logging_configuration.mode = atoi(value);
    }
    return 1;
}

int handler(void* config, const char* section, const char* name, const char* value) {
    if (strcmp(section, "layers") == 0) {
        return handle_section_layers(config, name, value);
    } else if (strcmp(section, "block_align") == 0) {
        return handle_section_block_align(config, name, value);
    } else if (strcmp(section, "sfuse") == 0) {
        return handle_section_sfuse(config, name, value);
    } else if (strcmp(section, "log") == 0) {
        return handle_section_log(config, name, value);
    } else if (strcmp(section, "multi_loop") == 0) {
        return handle_section_multi_loop(config, name, value);
    } else if (strcmp(section, "dedup") == 0) {
        return handle_section_dedup(config, name, value);
    } else if (strcmp(section, "compress") == 0) {
        return handle_section_compress(config, name, value);
    } else if (strcmp(section, "remote") == 0) {
        return handle_section_remote(config, name, value);
    } else if (strcmp(section, "local") == 0) {
        return handle_section_local(config, name, value);
    } else {
        return 0;
    }
    return 1;
}

int init_config(char* configuration_file_path, configuration** config) {
    configuration* pconfig = malloc(sizeof(struct sds_configuration));
    // This pointers are allocated when the first element is inserted.
    pconfig->layers = NULL;
    (pconfig->m_loop_config).loop_paths = NULL;
    
    (pconfig->block_config).block_size = 0;
    (pconfig->block_config).mode = 0;
    (pconfig->enc_config).block_size = 0;
    (pconfig->enc_config).align_mode = 0;

    (pconfig->block_config).block_size = 0;
    (pconfig->block_config).mode = 0;
    (pconfig->enc_config).block_size = 0;
    (pconfig->enc_config).align_mode = 0;
    
    if (ini_parse(configuration_file_path, handler, pconfig) < 0) {
        DEBUG_MSG("Configuration could not be loaded.\n");
        return 1;
    }
    //GSList* current = pconfig->m_loop_config.loop_paths;
    *config = pconfig;
    return 0;
}

void clean_config(configuration* config) {
    g_slist_free(config->layers);
    g_slist_free((config->m_loop_config).loop_paths);

    // free((config->enc_config).key);
    // free((config->enc_config).iv);
    free(config);


}
