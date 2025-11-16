/**
 * Tony Givargis
 * Copyright (C), 2023-2025
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * logfs.c
 */

#include <pthread.h>
#include "device.h"
#include "logfs.h"
#include "system.h"
#include <stdlib.h>

#define WCACHE_BLOCKS 32
#define RCACHE_BLOCKS 256

/*
*   Edited by Alexander Sanna
*   November 15th, 2025 
*   Operating Systems Fall 2025 - Tony Givargis

*   Description:
*   IMplementation of key/value storage system on a raw block dev.
*   Project was created and tested with a real device (30GB USB Flash)
*   
    *** IMPORTANT NOTE: Device used in testing has a 512kb block size. this is designed specifically for that.
*/

/**
 * Needs:
 *   pthread_create()
 *   pthread_join()
 *   pthread_mutex_init()
 *   pthread_mutex_destroy()
 *   pthread_mutex_lock()
 *   pthread_mutex_unlock()
 *   pthread_cond_init()
 *   pthread_cond_destroy()
 *   pthread_cond_wait()
 *   pthread_cond_signal()
 */

/* research the above Needed API and design accordingly */

struct logfs{
    uint64_t size;
    uint64_t capacity; 
    uint64_t head, tail;
    void* wbuf_;
    void* wbuf;
    pthread_mutex_t lock; 
    struct device* device;
    uint64_t offset;
    pthread_cond_t Data_avail;
    pthread_cond_t Space_avail;
    pthread_t worker;
};

struct logfs *logfs_open(const char *pathname)
{
    struct logfs * logfs = malloc(sizeof(struct logfs));
    if(logfs == NULL){return NULL;}

    logfs -> device = device_open(pathname);
    if(logfs->device == NULL){return NULL;}

    logfs -> capacity = device_block(logfs->device) * 10;

    logfs -> size = 0;
    logfs -> head = 0;
    logfs -> tail = 0;
    logfs->offset = 0;


    logfs -> wbuf_ = malloc(logfs->capacity + page_size());
    logfs->wbuf = memory_align(logfs->wbuf_, page_size());

    pthread_create(&logfs->worker, NULL, worker_func, logfs);
    pthread_mutex_init(&logfs->lock, NULL);
    pthread_cond_init(&logfs -> Data_avail, NULL);
    pthread_cond_init(&logfs -> Space_avail, NULL);


    return logfs;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len)
{
    if(logfs->capacity < len + logfs -> offset)
    {
        return -1; /*not enough space for append.*/
    }

    /*Activate lock, we will be modifying the wbuf that is accessible by both threads.*/

    pthread_mutex_lock(&logfs->lock);

    while(logfs->capacity - logfs->size < len)
    {
        pthread_cond_wait(&logfs->Space_avail, &logfs->lock);
    }

    if (logfs->tail + len <= logfs->capacity) 
    {
        /*Simple case: one memcpy*/
        memcpy(logfs->wbuf + logfs->tail, buf, len);
    } else {
    // Wraparound case: two memcpy calls
        uint64_t first_chunk = logfs->capacity - logfs->tail;
        memcpy(logfs->wbuf + logfs->tail, buf, first_chunk);

        uint64_t second_chunk = len - first_chunk;
        memcpy(logfs->wbuf, buf + first_chunk, second_chunk);
    }


    logfs->tail = (logfs->tail + len) % logfs->capacity;
    logfs->size += len;
    logfs->offset += len;

    pthread_cond_signal(&logfs->Data_avail);

    /*All done with buffer, never forget to unlock!*/
    pthread_mutex_unlock(&logfs->lock);

    return 0;
}
int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len);

void* worker_func(void* arg){
    struct logfs *logfs = (struct logfs *)arg; /*we passed in the logfs struct.*/
    uint64_t block_size = device_block(logfs->device);
    uint64_t device_offset = 0;  // Local variable tracking device position

    while(1)
    {
        pthread_mutex_lock(&logfs->lock);
        while(logfs->size < block_size)
        {
            pthread_cond_wait(&logfs->Data_avail, &logfs->lock);
        }

        pthread_mutex_unlock(&logfs->lock);
        device_write(logfs->device, logfs->wbuf + logfs->head, block_size, device_offset);
        device_offset += block_size;  // Update local tracking   
        
        pthread_mutex_lock(&logfs->lock);
        logfs->head = (logfs->head + block_size) % logfs->capacity;
        logfs->size -= block_size;

        pthread_cond_signal(&logfs->Space_avail);
        pthread_mutex_unlock(&logfs->lock);

    }
}

void logfs_close(struct logfs *logfs);
