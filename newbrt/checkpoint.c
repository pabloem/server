/* -*- mode: C; c-basic-offset: 4 -*- */
#ident "Copyright (c) 2009 Tokutek Inc.  All rights reserved."
 
#ident "The technology is licensed by the Massachusetts Institute of Technology, Rutgers State University of New Jersey, and the Research Foundation of State University of New York at Stony Brook under United States of America Serial No. 11/760379 and to the patents and/or patent applications resulting from it."

#ident "$Id$"


/***********
 * The purpose of this file is to implement the high-level logic for 
 * taking a checkpoint.
 *
 * There are three locks used for taking a checkpoint.  They are:
 *
 * NOTE: The reader-writer locks may be held by either multiple clients 
 *       or the checkpoint function.  (The checkpoint function has the role
 *       of the writer, the clients have the reader roles.)
 *
 *  - multi_operation_lock
 *    This is a new reader-writer lock.
 *    This lock is held by the checkpoint function only for as long as is required to 
 *    to set all the "pending" bits and to create the checkpoint-in-progress versions
 *    of the header and translation table (btt).
 *    The following operations must take the multi_operation_lock:
 *       - insertion into multiple indexes
 *       - "replace-into" (matching delete and insert on a single key)
 *
 *  - checkpoint_safe_lock
 *    This is a new reader-writer lock.
 *    This lock is held for the entire duration of the checkpoint.
 *    It is used to prevent more than one checkpoint from happening at a time
 *    (the checkpoint function is non-re-entrant), and to prevent certain operations
 *    that should not happen during a checkpoint.  
 *    The following operations must take the checkpoint_safe lock:
 *       - open a dictionary
 *       - close a dictionary
 *       - delete a dictionary
 *       - truncate a dictionary
 *       - rename a dictionary
 *
 *  - ydb_big_lock
 *    This is the existing lock used to serialize all access to tokudb.
 *    This lock is held by the checkpoint function only for as long as is required to 
 *    to set all the "pending" bits and to create the checkpoint-in-progress versions
 *    of the header and translation table (btt).
 *    
 * Once the "pending" bits are set and the snapshots are take of the header and btt,
 * most normal database operations are permitted to resume.
 *
 *
 *
 *****/

#include <stdio.h>

#include "brttypes.h"
#include "toku_portability.h"
#include "cachetable.h"
#include "checkpoint.h"

static toku_pthread_rwlock_t checkpoint_safe_lock;
static toku_pthread_rwlock_t multi_operation_lock;

static void (*ydb_lock)(void)   = NULL;
static void (*ydb_unlock)(void) = NULL;

// Note following static functions are called from checkpoint internal logic only,
// and use the "writer" calls for locking and unlocking.


static void 
multi_operation_lock_init(void) {
    int r = toku_pthread_rwlock_init(&multi_operation_lock, NULL); 
    assert(r == 0);
}

static void 
multi_operation_lock_destroy(void) {
    int r = toku_pthread_rwlock_destroy(&multi_operation_lock); 
    assert(r == 0);
}

static void 
multi_operation_checkpoint_lock(void) {
    int r = toku_pthread_rwlock_wrlock(&multi_operation_lock);   
    assert(r == 0);
}

static void 
multi_operation_checkpoint_unlock(void) {
    int r = toku_pthread_rwlock_wrunlock(&multi_operation_lock); 
    assert(r == 0);
}


static void 
checkpoint_safe_lock_init(void) {
    int r = toku_pthread_rwlock_init(&checkpoint_safe_lock, NULL); 
    assert(r == 0);
}

static void 
checkpoint_safe_lock_destroy(void) {
    int r = toku_pthread_rwlock_destroy(&checkpoint_safe_lock); 
    assert(r == 0);
}

static void 
checkpoint_safe_checkpoint_lock(void) {
    int r = toku_pthread_rwlock_wrlock(&checkpoint_safe_lock);   
    assert(r == 0);
}

static void 
checkpoint_safe_checkpoint_unlock(void) {
    int r = toku_pthread_rwlock_wrunlock(&checkpoint_safe_lock); 
    assert(r == 0);
}


// toku_xxx_client_(un)lock() functions are only called from client code,
// never from checkpoint code, and use the "reader" interface to the lock functions.

void 
toku_multi_operation_client_lock(void) {
    int r = toku_pthread_rwlock_rdlock(&multi_operation_lock);   
    assert(r == 0);
}

void 
toku_multi_operation_client_unlock(void) {
    int r = toku_pthread_rwlock_rdunlock(&multi_operation_lock); 
    assert(r == 0);
}

void 
toku_checkpoint_safe_client_lock(void) {
    int r = toku_pthread_rwlock_rdlock(&checkpoint_safe_lock);   
    assert(r == 0);
}

void 
toku_checkpoint_safe_client_unlock(void) {
    int r = toku_pthread_rwlock_rdunlock(&checkpoint_safe_lock); 
    assert(r == 0);
}


static BOOL initialized = FALSE;

// Initialize the checkpoint mechanism, must be called before any client operations.
void 
toku_checkpoint_init(void (*ydb_lock_callback)(void), void (*ydb_unlock_callback)(void)) {
    ydb_lock   = ydb_lock_callback;
    ydb_unlock = ydb_unlock_callback;
    multi_operation_lock_init();
    checkpoint_safe_lock_init();
    initialized = TRUE;
}

void toku_checkpoint_destroy(void) {
    multi_operation_lock_destroy();
    checkpoint_safe_lock_destroy();
    initialized = FALSE;
}


// Take a checkpoint of all currently open dictionaries
int 
toku_checkpoint(CACHETABLE ct, TOKULOGGER logger, char **error_string) {
    int r;

    printf("Yipes, checkpoint is being tested\n");

    assert(initialized);
    multi_operation_checkpoint_lock();
    checkpoint_safe_checkpoint_lock();
    ydb_lock();

    r = toku_cachetable_begin_checkpoint(ct, logger);

    multi_operation_checkpoint_unlock();
    ydb_unlock();
    if (r==0) {
	r = toku_cachetable_end_checkpoint(ct, logger, error_string);
    }

    checkpoint_safe_checkpoint_unlock();
    
    return r;
}