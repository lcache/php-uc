#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_uc.h"
#include <pthread.h>

ZEND_DECLARE_MODULE_GLOBALS(uc)

static zend_function_entry uc_functions[] = {
    PHP_FE(uc_test, NULL)
    {NULL, NULL, NULL}
};

zend_module_entry uc_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_UC_EXTNAME,
    uc_functions,
    PHP_MINIT(uc),
    PHP_MSHUTDOWN(uc),
    PHP_RINIT(uc),
    NULL,
    NULL,
    PHP_UC_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_UC
ZEND_GET_MODULE(uc)
#endif

PHP_INI_BEGIN()
	STD_PHP_INI_ENTRY("uc.storage_directory", "/var/tmp/php-uc", PHP_INI_SYSTEM, OnUpdateString, storage_directory, zend_uc_globals, uc_globals)
PHP_INI_END()

static void php_uc_init_globals(zend_uc_globals *uc_globals)
{
}

PHP_RINIT_FUNCTION(uc)
{
    return SUCCESS;
}

PHP_MINIT_FUNCTION(uc)
{
    ZEND_INIT_MODULE_GLOBALS(uc, php_uc_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    rocksdb_options_t *options = rocksdb_options_create();

    char *err = NULL;

    rocksdb_options_set_create_if_missing(options, 1);
    UC_G(db_handle) = rocksdb_open(options, UC_G(storage_directory), &err);

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Opening the database failed.");
        return FAILURE;
    }

    rocksdb_free(err);
    err = NULL;

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(uc)
{
    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

PHP_FUNCTION(uc_test)
{
    RETURN_STRING("UC Test");
}

// uc_fetch
// uc_store
// uc_inc
// uc_dec
// uc_clear_cache
// uc_delete
// UCIterator

PHP_FUNCTION(uc_fetch)
{
    RETURN_STRING("UC Test");
}
