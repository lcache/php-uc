#ifndef PHP_UC_H
#define PHP_UC_H 1

#ifdef ZTS
#include "TSRM.h"
#endif

#include <rocksdb/c.h>
#include <pthread.h>

ZEND_BEGIN_MODULE_GLOBALS(uc)
    char *storage_directory;
    rocksdb_t *db_handle;
    rocksdb_column_family_handle_t* cf_handles[3];
    pthread_mutex_t counter_lock;
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

extern zend_module_entry uc_module_entry;
#define phpext_uc_prt &uc_module_entry

#endif
