#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "workers.h"
#include "persistence.h"

int uc_workers_choose_and_lock(uc_worker_pool_t* wp, worker_t** available)
{
    int retval;
    *available = NULL;

    // @TODO: Process/thread affinity would help here.
    for (size_t id = 0; id < wp->workers_count; id++) {
        retval = pthread_mutex_trylock(&wp->workers[id].in_use_l);
        if (0 == retval) {
            *available = &wp->workers[id];
            //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Picked worker: %lu", id);
            break;
        }
        else if (EBUSY != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_trylock for in_use_l: %s", strerror(retval));
            return retval;
        }
    }

    // @TODO: Add handling to wait on the open_workers condition variable and try again.
    if (NULL == available) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed to store to user cache: no workers available");
        return EIO;
    }

    // Acquire the lock in order to write.
    retval = pthread_mutex_lock(&(*available)->server_l);
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_choose_and_lock: failed pthread_mutex_lock for server_l: %s", strerror(retval));
        return retval;
    }

    // Reset the worker's structure.
    // @TODO: Only run this for debugging.
    //memset(&(*available)->m, 0, sizeof(uc_metadata_t));
    //(*available)->kl = 0;
    //memset(&(*available)->k, 0, MAX_KEY_LENGTH);
    //(*available)->vl = 0;
    //memset(&(*available)->v, 0, MAX_VALUE_SIZE);
    return 0;
}

int uc_workers_complete_rpc(worker_t* w)
{
    int retval;

    // Validate metadata.
    //retval = uc_read_metadata(w->v, w->vl, NULL);
    //if (0 != retval) {
    //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: failed uc_read_metadata: %s", strerror(retval));
    //    return retval;
    //}

    // Verify that server_l is not currently held.
    // @TODO: Remove this when not debugging.
    /*
    retval = pthread_mutex_trylock(&w->server_l);
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: server_l is not available: %s", strerror(retval));
        return retval;
    }
    retval = pthread_mutex_unlock(&w->server_l);
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: pthread_mutex_unlock: %s", strerror(retval));
        return retval;
    }
    */

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_workers_complete_rpc: acquiring client lock for worker %lu", w->id);

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_workers_complete_rpc: sending signal to the server %lu", w->id);

    // Signal to the worker to respond. The worker should already be waiting on
    // server and ready to obtain server_l once we release it in
    // pthread_cond_wait below.
    w->rl = kWaitingOnServer;
    retval = pthread_cond_signal(&w->server);
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: failed pthread_cond_signal for server: %s", strerror(retval));
        return retval;
    }

    // We are done writing, so we can release the lock.
    retval = pthread_mutex_unlock(&w->server_l);
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: pthread_mutex_unlock: %s", strerror(retval));
        return retval;
    }

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_workers_complete_rpc: waiting for signal from worker %lu to client", w->id);


    // Wait on a state change. pthread_cond_wait will also release server_l.
    while (kWaitingOnServer == w->l) {
        // Re-acquire the lock so we can wait on the CV.
        retval = pthread_mutex_lock(&w->server_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: failed pthread_mutex_lock: %s", strerror(retval));
            return retval;
        }
        retval = pthread_cond_wait(&w->server, &w->server_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: failed pthread_cond_wait for server: %s", strerror(retval));
            return 0;
        }
        // Unlock in preparation for a fresh lock to wait on the CV.
        retval = pthread_mutex_unlock(&w->server_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "uc_workers_complete_rpc: pthread_mutex_unlock: %s", strerror(retval));
            return retval;
        }
    }

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_workers_complete_rpc: reacquired lock from worker %lu", w->id);

    return 0;
}

int uc_workers_unlock(worker_t* w) {
    int retval;

    if (NULL == w) {
        return 0;
    }

    //retval = pthread_mutex_unlock(&w->server_l);
    //if (0 != retval) {
    //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_unlock for server_l: %s", strerror(retval));
    //    return retval;
    //}

    retval = pthread_mutex_unlock(&w->in_use_l);
    if (0 != retval) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_unlock: %s", strerror(retval));
        return retval;
    }

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Unlocked worker %lu", w->id);

    // Let others know there's an open worker.
    //retval = pthread_cond_signal(available->ow);
    //if (0 != retval) {
    //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_signal on ow: %s", strerror(retval));
    //    return retval;
    //}

    return 0;
}


int worker_get(const uc_persistence_t* p, const char* key, size_t key_len, char* val, size_t* val_size)
{
    int retval = 0;
    char* err = NULL;
    rocksdb_readoptions_t* roptions = rocksdb_readoptions_create();
    char* value;
    value = rocksdb_get_cf(p->db_h, roptions, p->cf_h, key, key_len, val_size, &err);

    if (NULL != err) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] worker_get: failed rocksdb_get_cf: %s", pthread_self(), err);
        rocksdb_free(err);
        retval = EIO;
        goto cleanup;
    }

    // Miss
    // @TODO: Communicate this more semantically.
    if (NULL == value) {
        *val_size = 0;
    }

    if (*val_size > MAX_VALUE_SIZE) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] worker_get: stored data size (%lu) is more than the max a worker can handle (%lu)", pthread_self(), *val_size, MAX_VALUE_SIZE);
        retval = ENOMEM;
        goto cleanup;
    }

    if (*val_size > 0) {
        memcpy(val, value, *val_size);
    }

cleanup:
    rocksdb_readoptions_destroy(roptions);
    rocksdb_free(value);

    return retval;
}


int worker_write(const uc_persistence_t* p, const char* key, size_t key_len, const char* val, const size_t val_size, const uc_metadata_t meta)
{
    int retval = 0;
    char* err = NULL;
    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    rocksdb_writeoptions_t* woptions = rocksdb_writeoptions_create();

    if (meta.op == kPut) {
        rocksdb_writebatch_put_cf(wb, p->cf_h, key, key_len, val, val_size);
    }
    else if (meta.op == kDelete) {
        rocksdb_writebatch_delete_cf(wb, p->cf_h, key, key_len);
    }
    else if (meta.op == kInc || meta.op == kAdd || meta.op == kCAS) {
        rocksdb_writebatch_merge_cf(wb, p->cf_h, key, key_len, val, val_size);
    }
    else {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] worker_write: invalid operation: %d", pthread_self(), meta.op);
        retval = EINVAL;
        goto cleanup;
    }

    // Write the batch to storage.
    rocksdb_writeoptions_disable_WAL(woptions, 1);
    rocksdb_write(p->db_h, woptions, wb, &err);

    if (NULL != err) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] worker_write: failed rocksdb_write: %s", pthread_self(), err);
        rocksdb_free(err);
        retval = EIO;
    }

cleanup:
    rocksdb_writeoptions_destroy(woptions);
    rocksdb_writebatch_destroy(wb);

    return retval;
}

static void* slot_worker(void *arg)
{
    int retval;
    int success;
    worker_t *w = arg;
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Starting", w->id);

    while(1) {
        retval = pthread_mutex_lock(&w->server_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_mutex_lock: %s", w->id, strerror(retval));
            return NULL;
        }

        while (kWaitingOnClient == w->rl && kRunning == w->l) {
            //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Waiting", w->id);
            // Wait for a request (unlocks server_l).
            retval = pthread_cond_wait(&w->server, &w->server_l);
            if (0 != retval) {
                syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_cond_wait: %s", w->id, strerror(retval));
                return NULL;
            }
        }

        if (kStopping == w->l) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Stopping", w->id);
            retval = pthread_mutex_unlock(&w->server_l);
            if (0 != retval) {
                syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_mutex_unlock on stop: %s", w->id, strerror(retval));
            }
            return NULL;
        }

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Validating metadata", w->id);

        // Validate metadata.
        //retval = uc_read_metadata(w->v, w->vl, NULL);
        //if (0 != retval) {
        //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] slot_worker: uc_read_metadata: %s", w->id, strerror(retval));
        //    return NULL;
        //}

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Processing write", w->id);

        if (w->m.op == kGet) {
            retval = worker_get(w->p, w->k, w->kl, w->v, &w->vl);
            if (0 != retval) {
                syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed worker_get: %s", w->id, strerror(retval));
                return NULL;
            }
        } else {
            retval = worker_write(w->p, w->k, w->kl, w->v, w->vl, w->m);
            if (0 != retval) {
                syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed worker_write: %s", w->id, strerror(retval));
                return NULL;
            }
        }

        //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Write complete", w->id);
        // @TODO: Write anything back to the meta struct to signal success?

        w->rl = kWaitingOnClient;

        // Let the client know the request is complete.
        retval = pthread_cond_signal(&w->server);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] failed pthread_cond_signal for client: %s", w->id, strerror(retval));
            return NULL;
        }

        retval = pthread_mutex_unlock(&w->server_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_mutex_unlock on loop: %s", w->id, strerror(retval));
            return NULL;
        }
    }

    return NULL;
}

int uc_workers_init(const uc_persistence_t* p, size_t workers_count, uc_worker_pool_t** wp)
{
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Initializing concurrency: %lu", workers_count);

    size_t comp = sizeof(worker_t) - sizeof(size_t) * 2 - MAX_KEY_LENGTH - MAX_VALUE_SIZE;

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "worker_t needs padding: %lu", comp % 8);

    // Initialize concurrency.
    int retval;
    uc_worker_pool_t* pool;

    *wp = NULL;

    size_t mmap_size = sizeof(uc_worker_pool_t) + sizeof(worker_t) * workers_count;
    //int fd;
    //char mmap_template[] = "/tmp/php-uc.XXXXXX";

    //fd = mkstemp(mmap_template);
    //posix_fallocate(fd, 0, mmap_size);
    pool = (uc_worker_pool_t*) mmap(0, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    //close(fd);

    pool->workers_count = workers_count;

    // Mutex attributes
    pthread_mutexattr_t attr_mutex;
    retval = pthread_mutexattr_init(&attr_mutex);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutexattr_init: %s", strerror(retval));
        return retval;
    }
    retval = pthread_mutexattr_setpshared(&attr_mutex, PTHREAD_PROCESS_SHARED);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutexattr_setpshared: %s", strerror(retval));
        return retval;
    }
    retval = pthread_mutexattr_settype(&attr_mutex, PTHREAD_MUTEX_ADAPTIVE_NP);
    //retval = pthread_mutexattr_settype(&attr_mutex, PTHREAD_MUTEX_ERRORCHECK);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutexattr_settype: %s", strerror(retval));
        return retval;
    }

    // Mutexes
    //retval = pthread_mutex_init(UC_G(open_worker_lock), &attr_mutex);
    //if (retval != 0) {
    //   php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed pthread_mutex_init for open_worker_lock: %s", strerror(retval));
    //    return FAILURE;
    //}
    for (int i = 0; i < workers_count; i++) {
        retval = pthread_mutex_init(&pool->workers[i].in_use_l, &attr_mutex);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_init for use_l: %s", strerror(retval));
            return retval;
        }
        retval = pthread_mutex_init(&pool->workers[i].server_l, &attr_mutex);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_init for req_l: %s", strerror(retval));
            return retval;
        }
        retval = pthread_mutex_init(&pool->workers[i].client_l, &attr_mutex);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_init for req_l: %s", strerror(retval));
            return retval;
        }
    }
    retval = pthread_mutexattr_destroy(&attr_mutex);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutexattr_destroy: %s", strerror(retval));
        return retval;
    }

    // Condition variable attributes
    pthread_condattr_t attr_cvar;
    retval = pthread_condattr_init(&attr_cvar);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutexattr_init: %s", strerror(retval));
        return retval;
    }
    retval = pthread_condattr_setpshared(&attr_cvar, PTHREAD_PROCESS_SHARED);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_condattr_setpshared: %s", strerror(retval));
        return retval;
    }

    // Condition variables
    //retval = pthread_cond_init(UC_G(open_worker), &attr_cvar);
    //if (retval != 0) {
    //    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_init for open_worker: %s", strerror(retval));
    //    return retval;
    //}
    for (size_t i = 0; i < workers_count; i++) {
        retval = pthread_cond_init(&pool->workers[i].server, &attr_cvar);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_init for req: %s", strerror(retval));
            return retval;
        }
        retval = pthread_cond_init(&pool->workers[i].client, &attr_cvar);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_init for req: %s", strerror(retval));
            return retval;
        }
    }
    retval = pthread_condattr_destroy(&attr_cvar);
    if (retval != 0) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_condattr_destroy: %s", strerror(retval));
        return retval;
    }

    // Threads
    for (size_t id = 0; id < workers_count; id++) {
        pool->workers[id].ow = &pool->open_worker;
        pool->workers[id].id = id;
        pool->workers[id].p = p;
        retval = pthread_create(&pool->workers[id].td, NULL, &slot_worker, &pool->workers[id]);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_create: %s", strerror(retval));
            return retval;
        }
    }

    *wp = pool;

    return 0;
}

int uc_workers_destroy(uc_worker_pool_t* wp)
{
    int retval;
    for (size_t id = 0; id < wp->workers_count; id++) {
        wp->workers[id].l = kStopping;
        retval = pthread_cond_signal(&wp->workers[id].server);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_signal: %s", strerror(retval));
            return retval;
        }
        pthread_join(wp->workers[id].td, NULL);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_join: %s", strerror(retval));
            return retval;
        }
    }
    return 0;
}
