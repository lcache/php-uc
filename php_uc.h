/*
  +----------------------------------------------------------------------+
  | UC                                                                   |
  +----------------------------------------------------------------------+
  | Copyright (c) 2015 The PHP Group                                     |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: David Strauss <david@davidstrauss.net>                      |
  +----------------------------------------------------------------------+
 */

#ifndef PHP_UC_H
#define PHP_UC_H 1

#ifdef ZTS
#include "TSRM.h"
#endif

#include <rocksdb/c.h>
#include <pthread.h>

#define MAX_KEY_LENGTH 512
#define MAX_VALUE_SIZE 2097152

typedef enum {
    kPut = 0,
    kInc = 1,
    kAdd = 2,
    kCAS = 3
} uc_operation_t;

typedef enum {
    kNone = 0,
    kSerialized = 1,
    kLong = 2
} uc_value_type_t;

typedef struct {
    uc_value_type_t value_type;
    long value;
    long cas_value_or_inc;
    size_t ttl;
    time_t created;
    time_t modified;
    uc_operation_t op;
    size_t version;
    uint32_t magic;
} uc_metadata_t;

typedef enum {
    kRunning = 0,
    kStopping = 1
} lifecycle_t;

typedef struct {
    size_t i;
    lifecycle_t l;
    pthread_mutex_t use_l;
    pthread_mutex_t req_l;
    pthread_cond_t req;
    pthread_mutex_t resp_l;
    pthread_cond_t resp;
    pthread_cond_t* ow;
    pthread_t td;
    uc_metadata_t m;
    size_t kl;
    char k[MAX_KEY_LENGTH];
    size_t vl;
    char v[MAX_VALUE_SIZE];
} worker_t;

ZEND_BEGIN_MODULE_GLOBALS(uc)
    zend_bool enabled;
    char* storage_directory;
    rocksdb_t* db_h;
    rocksdb_options_t* db_options;
    rocksdb_options_t* cf_options;
    rocksdb_compactionfilter_t* cfilter;
    rocksdb_column_family_handle_t* cf_h;
    long concurrency;
    worker_t* workers;
    pthread_cond_t* open_worker;
    pthread_mutex_t* open_worker_lock;
ZEND_END_MODULE_GLOBALS(uc)

#ifdef ZTS
#define UC_G(v) TSRMG(uc_globals_id, zend_uc_globals *, v)
#else
#define UC_G(v) (uc_globals.v)
#endif

#define PHP_UC_VERSION "1.0"
#define PHP_UC_EXTNAME "uc"

PHP_MINIT_FUNCTION(uc);
PHP_MSHUTDOWN_FUNCTION(uc);
PHP_RINIT_FUNCTION(uc);

PHP_FUNCTION(uc_test);
PHP_FUNCTION(uc_compact);
PHP_FUNCTION(uc_clear_cache);
PHP_FUNCTION(uc_store);
PHP_FUNCTION(uc_fetch);
PHP_FUNCTION(uc_delete);
PHP_FUNCTION(uc_inc);
PHP_FUNCTION(uc_add);
PHP_FUNCTION(uc_cas);

extern zend_module_entry uc_module_entry;
#define phpext_uc_prt &uc_module_entry

#endif
