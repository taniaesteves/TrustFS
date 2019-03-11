/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#include "batch_blockalign.h"
#include <errno.h>
#include <stdio.h>

int B_BLOCKSIZE = 0;

void define_batch_block_size(block_align_config config) {
    B_BLOCKSIZE = config.block_size;
    // DEBUG_MSG("define_batch_block_size: batch_block_size - %d\n", B_BLOCKSIZE);
}

int batch_block_align_create(const char *path, mode_t mode, void *fi, struct fuse_operations nextlayer) {
    // DEBUG_MSG("batch_block_align_create: Path %s\n", path);

    ((struct fuse_file_info *)fi)->flags =
        ((((struct fuse_file_info *)fi)->flags & (~O_RDONLY)) & (~O_WRONLY)) | O_RDWR;

    return nextlayer.create(path, mode, fi);
}

int batch_block_align_open(const char *path, void *fi, struct fuse_operations nextlayer) {
    // DEBUG_MSG("batch_block_align_open: Path %s\n", path);
    ((struct fuse_file_info *)fi)->flags =
        ((((struct fuse_file_info *)fi)->flags & (~O_RDONLY)) & (~O_WRONLY)) | O_RDWR;

    return nextlayer.open(path, fi);
}

off_t batch_block_align_get_file_size(const char *path, struct fuse_file_info *fi, struct fuse_operations nextlayer) {
    struct stat st;

    if (fi != NULL) {
        nextlayer.fgetattr(path, &st, fi);
        // DEBUG_MSG("batch_block_align_get_file_size: fi is not null\n");
    } else {
        nextlayer.getattr(path, &st);
        // DEBUG_MSG("batch_block_align_get_file_size: fi is null\n");
    }

    return st.st_size;
}

int batch_read_block(char *buf, size_t size, uint64_t offset, struct batch_io_info *inf) {
    // DEBUG_MSG("batch_read_block: size %lu offset %lu\n", size, offset);
    // read to the buffer by calling the next layer
    return inf->nextlayer.read(inf->path, buf, size, offset, inf->fi);
}

int batch_process_read_block(char *buf, size_t size, uint64_t aligned_offset, int init_extra_offset, int end_extra_offset, struct batch_io_info *inf) {
    // DEBUG_MSG("batch_process_read_block: BATCH: batch_process_read_block\n");
    //Result of read operation
    int res;
    
    //max bytes to read. The B_BLOCKSIZE is due to the extra bytes we may need to read due to alignement issues (begin/end extra offset).
    uint64_t max_size_read=size+(B_BLOCKSIZE*2);

    //pad size that needs to be read in case the last full block must be read
    int pad=0;

    //bytes to read, actual size + extra offset if read is not aligned
    uint64_t bytes_to_read=size+init_extra_offset;

    //BUffer with content to be read
    char read_buf[max_size_read];

    // DEBUG_MSG("batch_process_read_block: Process READ file Path %s, and block offset %llu, extra_offset %llu, size %zu\n",inf->path,(unsigned long long int) aligned_offset, (unsigned long long int) init_extra_offset , size);

    //If we want to read less than a block then we must read the full block
    if(bytes_to_read<=B_BLOCKSIZE){
        bytes_to_read=B_BLOCKSIZE;
    }else{
        //if we are reading some byts at the last block (not aligned with the final block)
        if(end_extra_offset>0){
            //see the extra bytes that must be read and add them to the amount of bytes to read
            pad = B_BLOCKSIZE-end_extra_offset;
            bytes_to_read+= pad;
            // DEBUG_MSG("batch_process_read_block: end_extra_offset %d -- %d -- %llu\n", end_extra_offset, pad, bytes_to_read);
        }
        
    }

    res = batch_read_block(read_buf, bytes_to_read, aligned_offset,inf);
    //If the number of bytes read is smaller than the extra offset something is wrong. Maybe We are reading past the file size
    if(res<init_extra_offset){
        ERROR_MSG("batch_process_read_block: res < init_extra_offset - Read done file Path %s, and block offset %llu, extra_offset %llu, size %zu, res %d\n",
                  inf->path, (unsigned long long int)aligned_offset, (unsigned long long int)init_extra_offset, size,
                  res);
        return -1;
    }

    //Now we need to return the result of the read operation with the appropriate size
    if(res-init_extra_offset > size){
        //if the new bytes read are higher than size (excluding the extra initial bytes read)
        // just copy to the response buffer the size bytes
        // DEBUG_MSG("batch_process_read_block: 1 - Read done file Path %s, and block offset %llu, extra_offset %llu, size %zu, res %d\n", inf->path,
        //       (unsigned long long int)aligned_offset, (unsigned long long int)init_extra_offset, size, res);
        memcpy(buf, &read_buf[init_extra_offset], size);
        return size;
    }
    else{
        //Else, maybe the read operation asked for more bytes than the file has
        //return the size of bytes read ((excluding the extra initial bytes read))
        // DEBUG_MSG("batch_process_read_block: 2 - Read done file Path %s, and block offset %llu, extra_offset %llu, size %zu, res %d\n", inf->path,
        //       (unsigned long long int)aligned_offset, (unsigned long long int)init_extra_offset, size, res);
        memcpy(buf, &read_buf[init_extra_offset], res -  init_extra_offset);
        return res-init_extra_offset;
    }

}

int batch_write_block(char *buf, size_t size, uint64_t offset, struct batch_io_info *inf) {
    // DEBUG_MSG("batch_write_block: Going to write %d with offset %llu\n", size, offset);
    // Write the buffer to the block by calling the next layer
    return inf->nextlayer.write(inf->path, buf, size, offset, inf->fi);
}

int process_block_incomplete(uint64_t offset, uint64_t pos, char *new_buf, size_t size, char *write_buf, struct batch_io_info *inf) {
    int res, write_buf_size;
    char aux_block[B_BLOCKSIZE];

    res = batch_read_block(aux_block, B_BLOCKSIZE, offset, inf);
    
    write_buf_size = (offset + res) > (pos + size) ? res : ((((pos + size) % B_BLOCKSIZE) == 0) ? B_BLOCKSIZE : ((pos + size) % B_BLOCKSIZE));    
    
    bzero(write_buf, write_buf_size);

    //copy the block bytes to the write buffer
    memcpy(write_buf, aux_block, res);
    //copy the new bytes that came in the request to the write buffer
    memcpy(&write_buf[pos-offset], new_buf, size);

    return write_buf_size;
}

int batch_process_write_block(char *buf, size_t size, uint64_t aligned_offset, int init_extra_offset, int end_extra_offset, struct batch_io_info *inf) {    
    //Result of write operation
    int res;
    int first_block_read=0;
    
    //max bytes to write. The B_BLOCKSIZE is due to the extra bytes we may need to read due to alignement issues (begin/end extra offset).
    uint64_t max_size_write=size+(B_BLOCKSIZE*2);

    //bytes to actually write to the storage
    uint64_t bytes_to_write=0;
    uint64_t bytes_remaining = size;

    //BUffer with the content actually to be written
    char write_buf[max_size_write];

    // DEBUG_MSG("batch_process_write_block: Process Write file Path %s, and block offset %llu, extra_offset %llu, size %zu\n",inf->path,(unsigned long long int)aligned_offset, (unsigned long long int) init_extra_offset , size);

    //if we are writing to an unaligned offset we must read the remaining bytes of the block
    int init_to_write = (size < (B_BLOCKSIZE-init_extra_offset)) ? size : B_BLOCKSIZE-init_extra_offset;
    if(init_extra_offset>0){
        first_block_read=1;
        res = process_block_incomplete(aligned_offset, aligned_offset+init_extra_offset, buf, init_to_write, write_buf, inf);
        bytes_to_write+=res; 
        bytes_remaining -= init_to_write;
    }

    // write aligned and complete blocks
    if ((bytes_remaining / B_BLOCKSIZE) > 0) {
        memcpy(&write_buf[bytes_to_write], &buf[size-bytes_remaining], bytes_remaining-(bytes_remaining % B_BLOCKSIZE));
        bytes_to_write += bytes_remaining-(bytes_remaining % B_BLOCKSIZE);
        bytes_remaining -= bytes_remaining-(bytes_remaining % B_BLOCKSIZE);
    }

    //Since we may be rewiriting only some bytes of a full block we need to read the last block touched by the request
    //Also we must check if the write operation is for more than 1 block.otherwise it was already read in the previous read call
    if (end_extra_offset>0 && (bytes_to_write>B_BLOCKSIZE || first_block_read==0)) {

        //TODO: this may be optimized with a cache
        //Get file size to know how many bytes we should read
        uint64_t filesize = batch_block_align_get_file_size(inf->path, inf->fi, inf->nextlayer);
    
        if (aligned_offset+bytes_to_write+bytes_remaining < filesize) {
            if ((init_extra_offset+size > B_BLOCKSIZE) || ((init_extra_offset+size < B_BLOCKSIZE) && first_block_read==0)) {                
                res = process_block_incomplete(aligned_offset+bytes_to_write, aligned_offset+bytes_to_write, &buf[size-bytes_remaining], bytes_remaining, &write_buf[bytes_to_write], inf);
                bytes_to_write += res;
            }
        } else {
            memcpy(&write_buf[bytes_to_write], &buf[size-bytes_remaining], bytes_remaining);
            bytes_to_write += bytes_remaining;
        }
    } 

    // DEBUG_MSG("batch_process_write_block: going to write %lu bytes to offset %lu\n", bytes_to_write, aligned_offset);
    res = batch_write_block(write_buf, bytes_to_write, aligned_offset, inf);
    if(res<bytes_to_write){
        ERROR_MSG(" error Bytes write %s\n", strerror(res));
        return -1;
    }

    return size;
}


int batch_block_align_op(const char *path, char *buf, size_t size, int io_type, off_t offset, void *fi, struct fuse_operations nextlayer) {
    // DEBUG_MSG("batch_block_align_op: Entering function block_align_write with the following arguments.\n");
    // DEBUG_MSG("batch_block_align_op: Path %s,  offset %llu, size %zu\n", path, (unsigned long long int)offset, size);

   //if the offset to write is not aligned with a block, we need to know where the write is positioned in the block (extra_bytes)
    int init_extra_offset=offset%B_BLOCKSIZE;
    
    //the offset where the block starts is the offset to write minus the extra bytes
    uint64_t aligned_offset = offset - init_extra_offset;

    //if the offset to write is not aligned with the last block, we need to know where the write is positioned in the block (extra_bytes)
    int end_extra_offset=(offset+size)%B_BLOCKSIZE;

    struct batch_io_info inf;
    inf.fi = fi;
    inf.path = path;
    inf.nextlayer = nextlayer;

    int res=0;
    if(io_type==WRITE){
        res = batch_process_write_block(buf, size, aligned_offset, init_extra_offset, end_extra_offset, &inf); 
    } else{
        res = batch_process_read_block(buf, size, aligned_offset, init_extra_offset, end_extra_offset, &inf);   
    }
    return res;

}

int batch_block_align_read(const char *path, char *buf, size_t size, off_t offset, void *fi, struct fuse_operations nextlayer){    
    return batch_block_align_op(path, buf, size, READ, offset, fi, nextlayer);
}

int batch_block_align_write(const char *path, const char *buf, size_t size, off_t offset, void *fi, struct fuse_operations nextlayer){
    return batch_block_align_op(path, (char*) buf, size, WRITE, offset, fi, nextlayer);
}

int batch_block_align_truncate(const char *path, off_t size, struct fuse_file_info *fi_in, struct fuse_operations nextlayer) {
    struct stat stbuf;
    int res;
    struct fuse_file_info *fi;

    int extra_bytes = size % B_BLOCKSIZE;
    char buffer[extra_bytes];
    uint64_t block_offset = size / B_BLOCKSIZE * B_BLOCKSIZE;

    // Get file size
    //TODO: we can have cache here again
    if (fi_in == NULL) {
        res = nextlayer.getattr(path, &stbuf);
    } else {
        res = nextlayer.fgetattr(path, &stbuf, fi_in);
    }

    if (res < 0) {
        // DEBUG_MSG("batch_block_align_truncate: Truncate error getting size file %s\n", path);
        return res;
    }

    // DEBUG_MSG("batch_block_align_truncate: size truncate is %lu size is %lu\n", size, stbuf.st_size);

    // TODO in the future this can be optimized since open is not needed for al cases
    if (fi_in != NULL) {
        fi = fi_in;
    } else {
        fi = malloc(sizeof(struct fuse_file_info));
        fi->flags = O_RDWR;
        res = nextlayer.open(path, fi);
        if (res == -1) {
            // DEBUG_MSG("batch_block_align_truncate: Error truncate opening file %s truncate size is %lu\n", path, size);
            free(fi);
            return res;
        }
    }

    // CASE1
    // Size is higher than current file size
    if (size > stbuf.st_size) {
        off_t size_to_write = size - stbuf.st_size;
        off_t size_written = 0;
        int blocksize = 64 * 1024;
        uint64_t offset = stbuf.st_size;
        char buff[blocksize];
        bzero(buff, blocksize);

        while (size_written < size_to_write) {
            int iter_size = (blocksize < (size_to_write - size_written)) ? blocksize : size_to_write - size_written;

            // Fill the file with zeroes
            res = batch_block_align_write(path, buff, iter_size, offset, fi, nextlayer);
            if (res < iter_size) {
                // DEBUG_MSG("batch_block_align_truncate: Failed write %s iter_size is %d offset is %llu\n", path, iter_size,
                //           (unsigned long long int)offset);
                if (fi_in == NULL) {
                    free(fi);
                }
                return -1;
            }

            offset += iter_size;
            size_written += iter_size;
        }
    }
    // Size is smaller than current file size
    else {
        // If size is aligned with block there is no problem
        // Otherwise we must re-write the last block since it is written partially

        if (extra_bytes > 0) {
            // DEBUG_MSG("batch_block_align_truncate: read %s extra_bytes is %d offset is %llu\n", path, extra_bytes,
            //           (unsigned long long int)block_offset);

            res = batch_block_align_read(path, buffer, extra_bytes, block_offset, fi, nextlayer);
            if (res < extra_bytes) {
                // DEBUG_MSG("batch_block_align_truncate: Failed read %s extra_bytes is %d offset is %llu\n", path, extra_bytes,
                //           (unsigned long long int)block_offset);
                if (fi_in == NULL) {
                    free(fi);
                }
                return -1;
            }
        }
    }

    res = nextlayer.ftruncate(path, size, fi);
    if (res < 0) {
        // DEBUG_MSG("batch_block_align_truncate: Failed truncate %s size is %lu\n", path, size);
        if (fi_in == NULL) {
            free(fi);
        }
        return -1;
    }

    if (extra_bytes > 0 && size < stbuf.st_size) {
        struct batch_io_info inf;
        inf.fi = fi;
        inf.path = path;
        inf.nextlayer = nextlayer;

        res = batch_write_block(buffer, extra_bytes, block_offset, &inf);
        if (res < extra_bytes) {
            // DEBUG_MSG("batch_block_align_truncate: Failed write 2 %s iter_size is %d offset is %llu\n", path, extra_bytes,
            //           (unsigned long long int)block_offset);
            if (fi_in == NULL) {
                free(fi);
            }
            return -1;
        }
    }

    if (fi_in == NULL) {
        // DEBUG_MSG("batch_block_align_truncate: release new_path %s\n", path);
        res = nextlayer.release(path, fi);
        if (res < 0) {
            // DEBUG_MSG("batch_block_align_truncate: Failed releDase new_path %s\n", path);
            free(fi);
            return -1;
        }

        free(fi);
    }

    return 0;
}
