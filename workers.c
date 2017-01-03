#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/mman.h>
#include "workers.h"
#include "persistence.h"

int worker_write(const uc_persistence_t* p, char* key, size_t key_len, char* val, size_t val_size, uc_metadata_t meta) {
    int retval = 0;

    // Generate the write batch.
    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();

    if (meta.op == kPut) {
        rocksdb_writebatch_put_cf(wb, p->cf_h, key, key_len, val, val_size);
    } else {
        rocksdb_writebatch_merge_cf(wb, p->cf_h, key, key_len, val, val_size);
    }

    // Write the batch to storage.
    char* err = NULL;
    rocksdb_writeoptions_t* woptions;
    woptions = rocksdb_writeoptions_create();
    //rocksdb_writeoptions_disable_WAL(woptions, 1);
    rocksdb_write(p->db_h, woptions, wb, &err);

    if (NULL != err) {
        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed rocksdb_write: %s", pthread_self(), err);
        retval = EIO;
    }

    // Clean up.
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
        retval = pthread_mutex_lock(&w->resp_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_mutex_lock: %s", w->id, strerror(retval));
            return NULL;
        }

        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Waiting", w->id);

        // Wait for a request.
        retval = pthread_cond_wait(&w->resp, &w->resp_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_cond_wait: %s", w->id, strerror(retval));
            return NULL;
        }

        if (kStopping == w->l) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Stopping", w->id);
            retval = pthread_mutex_unlock(&w->resp_l);
            if (0 != retval) {
                syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_mutex_unlock on stop: %s", w->id, strerror(retval));
            }
            return NULL;
        }

        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Processing write", w->id);

        success = worker_write(w->k, w->kl, w->v, w->vl, w->m);
        if (!success) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed worker_write", w->id);
            return NULL;
        }

        syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "[%lu] Write complete", w->id);

        // @TODO: Write anything back to the meta struct to signal success?

        retval = pthread_cond_signal(&w->req);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_cond_signal on req: %s", w->id, strerror(retval));
            return NULL;
        }

        retval = pthread_mutex_unlock(&w->resp_l);
        if (0 != retval) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "[%lu] Failed pthread_mutex_unlock on loop: %s", w->id, strerror(retval));
            return NULL;
        }
    }

    return NULL;
}

int uc_workers_init(const uc_persistence_t* p, size_t workers_count, worker_pool_t** wp)
{
    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Initializing concurrency: %lu", UC_G(concurrency));

    // Initialize concurrency.
    int retval;
    *wp = (worker_pool_t*) mmap(NULL, sizeof(worker_pool_t) + sizeof(worker_t) * workers_count, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    (*wp)->workers_count = workers_count;

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

    // Mutexes
    //retval = pthread_mutex_init(UC_G(open_worker_lock), &attr_mutex);
    //if (retval != 0) {
    //   php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed pthread_mutex_init for open_worker_lock: %s", strerror(retval));
    //    return FAILURE;
    //}
    for (int i = 0; i < workers_count; i++) {
        retval = pthread_mutex_init(&(*wp)->workers[i].use_l, &attr_mutex);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_init for use_l: %s", strerror(retval));
            return retval;
        }
        retval = pthread_mutex_init(&(*wp)->workers[i].req_l, &attr_mutex);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_init for req_l: %s", strerror(retval));
            return retval;
        }
        retval = pthread_mutex_init(&(*wp)->workers[i].resp_l, &attr_mutex);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_mutex_init for resp_l: %s", strerror(retval));
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
        retval = pthread_cond_init(&(*wp)->workers[i].req, &attr_cvar);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_init for req: %s", strerror(retval));
            return retval;
        }
        retval = pthread_cond_init(&(*wp)->workers[i].resp, &attr_cvar);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_cond_init for resp: %s", strerror(retval));
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
        (*wp)->workers[id].ow = &(*wp)->open_worker;
        (*wp)->workers[id].id = id;
        retval = pthread_create(&(*wp)->workers[id].td, NULL, &slot_worker, &(*wp)->workers[id]);
        if (retval != 0) {
            syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_ERR), "Failed pthread_create: %s", strerror(retval));
            return retval;
        }
    }

    return 0;
}

int uc_workers_destroy(worker_pool_t* wp)
{
    int retval;
    for (size_t id = 0; id < wp->workers_count; id++) {
        wp->workers[id].l = kStopping;
        retval = pthread_cond_signal(&wp->workers[id].req);
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