/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#include "sgx_utils.h"
#include "../logging/logdef.h"

#define MAX_PATH FILENAME_MAX

void print_sgx_error_message(sgx_status_t err);

char* getEnclaveType(int enclaveType) {
    switch(enclaveType) {
        case ENCLAVE_PPL:
            return "PPL";
        case ENCLAVE_C:
            return "C";
    }
    return "Unkown enclave type";
}

int _sgx_create_enclave(sgx_enclave_id_t *eid, int enclaveType) {

    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    char *enclavefilepath;

    switch(enclaveType) {
        case ENCLAVE_PPL:
            strncpy(token_path, TOKEN_FILENAME_PPL, sizeof(TOKEN_FILENAME_PPL));
            enclavefilepath   = ENCLAVE_FILE_PPL;
            break;
        case ENCLAVE_C:
            strncpy(token_path, TOKEN_FILENAME_C, sizeof(TOKEN_FILENAME_C));
            enclavefilepath   = ENCLAVE_FILE_C;
            break;
        default:
            DEBUG_MSG("ERROR: Unkown enclave type!\n");
            exit(-1);
    }

    DEBUG_MSG("_sgx_create_enclave: creating enclave %d path %s token %s.\n", enclaveType, enclavefilepath, token_path);

    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved  */
    // DEBUG_MSG("launch token file \"%s\".\n", token_path);
    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        DEBUG_MSG("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            DEBUG_MSG("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclavefilepath, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_sgx_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }
    DEBUG_MSG("sgxCreateEnclave[%s] [%d]: Enclave created\n", getEnclaveType(enclaveType), (int) *eid);

    /* Step 3: save the launch token if it is updated */
    if (updated == 0 || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        DEBUG_MSG("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}


void print_sgx_error_message(sgx_status_t err) {
    switch(err) {
        case SGX_ERROR_INVALID_PARAMETER:             
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_PARAMETER\n", (int) err);
            break;
        case SGX_ERROR_INVALID_CPUSVN: 
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_CPUSVN\n", (int) err);
            break;
        case SGX_ERROR_INVALID_ISVSVN: 
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_ISVSVN\n", (int) err);
            break;
        case SGX_ERROR_MAC_MISMATCH: 
            DEBUG_MSG("[0x%x] SGX_ERROR_MAC_MISMATCH\n", (int) err);
            break;
        case SGX_ERROR_OUT_OF_MEMORY: 
            DEBUG_MSG("[0x%x] SGX_ERROR_OUT_OF_MEMORY\n", (int) err);
            break;
        case SGX_ERROR_UNEXPECTED: 
            DEBUG_MSG("[0x%x] SGX_ERROR_UNEXPECTED\n", (int) err);
            break;
        case SGX_ERROR_ENCLAVE_LOST:
            DEBUG_MSG("[0x%x] SGX_ERROR_ENCLAVE_LOST\n", (int) err);
            break;
        case SGX_ERROR_INVALID_STATE:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_STATE\n", (int) err);
            break;
        case SGX_ERROR_INVALID_FUNCTION:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_FUNCTION\n", (int) err);
            break;
        case SGX_ERROR_OUT_OF_TCS:
            DEBUG_MSG("[0x%x] SGX_ERROR_OUT_OF_TCS\n", (int) err);
            break;
        case SGX_ERROR_ENCLAVE_CRASHED:
            DEBUG_MSG("[0x%x] SGX_ERROR_ENCLAVE_CRASHED\n", (int) err);
            break;
        case SGX_ERROR_ECALL_NOT_ALLOWED:
            DEBUG_MSG("[0x%x] SGX_ERROR_ECALL_NOT_ALLOWED\n", (int) err);
            break;
        case SGX_ERROR_OCALL_NOT_ALLOWED:
            DEBUG_MSG("[0x%x] SGX_ERROR_OCALL_NOT_ALLOWED\n", (int) err);
            break;
        case SGX_ERROR_STACK_OVERRUN:
            DEBUG_MSG("[0x%x] SGX_ERROR_STACK_OVERRUN\n", (int) err);
            break;
        case SGX_ERROR_UNDEFINED_SYMBOL:
            DEBUG_MSG("[0x%x] SGX_ERROR_UNDEFINED_SYMBOL\n", (int) err);
            break;
        case SGX_ERROR_INVALID_ENCLAVE:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_ENCLAVE\n", (int) err);
            break;
        case SGX_ERROR_INVALID_ENCLAVE_ID:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_ENCLAVE_ID\n", (int) err);
            break;
        case SGX_ERROR_INVALID_SIGNATURE:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_SIGNATURE\n", (int) err);
            break;
        case SGX_ERROR_NDEBUG_ENCLAVE:
            DEBUG_MSG("[0x%x] SGX_ERROR_NDEBUG_ENCLAVE\n", (int) err);
            break;
        case SGX_ERROR_OUT_OF_EPC:
            DEBUG_MSG("[0x%x] SGX_ERROR_OUT_OF_EPC\n", (int) err);
            break;
        case SGX_ERROR_NO_DEVICE:
            DEBUG_MSG("[0x%x] SGX_ERROR_NO_DEVICE\n", (int) err);
            break;
        case SGX_ERROR_MEMORY_MAP_CONFLICT:
            DEBUG_MSG("[0x%x] SGX_ERROR_MEMORY_MAP_CONFLICT\n", (int) err);
            break;
        case SGX_ERROR_INVALID_METADATA:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_METADATA\n", (int) err);
            break;
        case SGX_ERROR_DEVICE_BUSY:
            DEBUG_MSG("[0x%x] SGX_ERROR_DEVICE_BUSY\n", (int) err);
            break;
        case SGX_ERROR_INVALID_VERSION:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_VERSION\n", (int) err);
            break;
        case SGX_ERROR_MODE_INCOMPATIBLE:
            DEBUG_MSG("[0x%x] SGX_ERROR_MODE_INCOMPATIBLE\n", (int) err);
            break;
        case SGX_ERROR_ENCLAVE_FILE_ACCESS:
            DEBUG_MSG("[0x%x] SGX_ERROR_ENCLAVE_FILE_ACCESS\n", (int) err);
            break;
        case SGX_ERROR_INVALID_MISC:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_MISC\n", (int) err);
            break;
        case SGX_ERROR_INVALID_ATTRIBUTE:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_ATTRIBUTE\n", (int) err);
            break;
        case SGX_ERROR_INVALID_KEYNAME:
            DEBUG_MSG("[0x%x] SGX_ERROR_INVALID_KEYNAME\n", (int) err);
            break;
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            DEBUG_MSG("[0x%x] SGX_ERROR_SERVICE_UNAVAILABLE\n", (int) err);
            break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            DEBUG_MSG("[0x%x] SGX_ERROR_SERVICE_TIMEOUT\n", (int) err);
            break;
        case SGX_ERROR_AE_INVALID_EPIDBLOB:
            DEBUG_MSG("[0x%x] SGX_ERROR_AE_INVALID_EPIDBLOB\n", (int) err);
            break;
        case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
            DEBUG_MSG("[0x%x] SGX_ERROR_SERVICE_INVALID_PRIVILEGE\n", (int) err);
            break;
        case SGX_ERROR_EPID_MEMBER_REVOKED:
            DEBUG_MSG("[0x%x] SGX_ERROR_EPID_MEMBER_REVOKED\n", (int) err);
            break;
        case SGX_ERROR_UPDATE_NEEDED:
            DEBUG_MSG("[0x%x] SGX_ERROR_UPDATE_NEEDED\n", (int) err);
            break;
        case SGX_ERROR_NETWORK_FAILURE:
            DEBUG_MSG("[0x%x] SGX_ERROR_NETWORK_FAILURE\n", (int) err);
            break;
        case SGX_ERROR_AE_SESSION_INVALID:
            DEBUG_MSG("[0x%x] SGX_ERROR_AE_SESSION_INVALID\n", (int) err);
            break;
        case SGX_ERROR_BUSY:
            DEBUG_MSG("[0x%x] SGX_ERROR_BUSY\n", (int) err);
            break;
        case SGX_ERROR_MC_NOT_FOUND:
            DEBUG_MSG("[0x%x] SGX_ERROR_MC_NOT_FOUND\n", (int) err);
            break;
        case SGX_ERROR_MC_NO_ACCESS_RIGHT:
            DEBUG_MSG("[0x%x] SGX_ERROR_MC_NO_ACCESS_RIGHT\n", (int) err);
            break;
        case SGX_ERROR_MC_USED_UP:
            DEBUG_MSG("[0x%x] SGX_ERROR_MC_USED_UP\n", (int) err);
            break;
        case SGX_ERROR_MC_OVER_QUOTA:
            DEBUG_MSG("[0x%x] SGX_ERROR_MC_OVER_QUOTA\n", (int) err);
            break;
        case SGX_ERROR_KDF_MISMATCH:
            DEBUG_MSG("[0x%x] SGX_ERROR_KDF_MISMATCH\n", (int) err);
            break;
        case SGX_ERROR_UNRECOGNIZED_PLATFORM:
            DEBUG_MSG("[0x%x] SGX_ERROR_UNRECOGNIZED_PLATFORM\n", (int) err);
            break;
        case SGX_ERROR_NO_PRIVILEGE:
            DEBUG_MSG("[0x%x] SGX_ERROR_NO_PRIVILEGE\n", (int) err);
            break;
        case SGX_ERROR_FILE_BAD_STATUS:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_BAD_STATUS\n", (int) err);
            break;
        case SGX_ERROR_FILE_NO_KEY_ID:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_NO_KEY_ID\n", (int) err);
            break;
        case SGX_ERROR_FILE_NAME_MISMATCH:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_NAME_MISMATCH\n", (int) err);
            break;
        case SGX_ERROR_FILE_NOT_SGX_FILE:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_NOT_SGX_FILE\n", (int) err);
            break;
        case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE\n", (int) err);
            break;
        case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE\n", (int) err);
            break;
        case SGX_ERROR_FILE_RECOVERY_NEEDED:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_RECOVERY_NEEDED\n", (int) err);
            break;
        case SGX_ERROR_FILE_FLUSH_FAILED:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_FLUSH_FAILED\n", (int) err);
            break;
        case SGX_ERROR_FILE_CLOSE_FAILED:
            DEBUG_MSG("[0x%x] SGX_ERROR_FILE_CLOSE_FAILED\n", (int) err);
            break;
        case SGX_SUCCESS:
            break;
        default:
            DEBUG_MSG("[0x%x] sgx error\n", err);
            break;
    }
}

/* OCALLS */

void uprint(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    DEBUG_MSG("%s", str);
    // fflush(stdout);
}

void usgx_exit_error(const char *error_msg) {
    DEBUG_MSG("usgx_exit: %s\n", error_msg);    
    exit(EXIT_FAILURE);
}

void usgx_exit(const char *func_name, int err) {
    DEBUG_MSG("usgx_exit: %s\n", func_name);
    print_sgx_error_message((sgx_status_t) err);
    exit(EXIT_FAILURE);
}


uint32_t save_sdata(uint8_t *sdata, uint32_t sdata_len) {
    // DEBUG_MSG("<U> SAVE KEY!!\n");

    char filename[32] = "/tmp/skey.priv";
    FILE *fp;

    fp = fopen(filename, "ab");
    if (fp != NULL) {
        // DEBUG_MSG("<U> Saving sealed key with size=%d\n", sdata_len);
        fwrite(sdata, 1, sdata_len, fp);
        fclose(fp);        
        return EXIT_SUCCESS;
    }
    DEBUG_MSG("<U> Can't open file\n");
    return EXIT_FAILURE;
}

uint32_t load_sdata(uint8_t *sdata, uint32_t sdata_len, uint32_t *sdata_len_out) {
    // DEBUG_MSG("<U> LOAD KEY!!\n");

    char filename[32] = "/tmp/skey.priv";
    FILE *fp;
    uint8_t *buffer;
    size_t nread = 0; 

    // file doesn't exist
    if (access(filename, F_OK) != EXIT_SUCCESS) return EXIT_FAILURE;
    
    errno = 0;
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        DEBUG_MSG("Can't open file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }    
    buffer = (uint8_t*) malloc(sizeof(uint8_t) * sdata_len);
    if (buffer == NULL) return EXIT_FAILURE;
    
    nread = fread(buffer, sizeof(uint8_t), sdata_len, fp);
    if ((nread * sizeof(uint8_t)) != sdata_len) {
        DEBUG_MSG("<U> wrong sealed ekey size! -> %lu -> %d\n", nread * sizeof(uint8_t), sdata_len);
        return EXIT_FAILURE;
    }
    fclose(fp);
    memcpy(sdata, buffer, sdata_len);
    *sdata_len_out = sdata_len;
    free(buffer); 

    return EXIT_SUCCESS;
}
