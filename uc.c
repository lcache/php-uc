/*
  +----------------------------------------------------------------------+
  | UC                                                                   |
  +----------------------------------------------------------------------+
  | Copyright (c) 2017 The PHP Group and David Strauss                   |
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
  |          Rasmus Lerdorf <rasmus@php.net>                             |
  |          Daniel Cowgill <dcowgill@communityconnect.com>              |
  +----------------------------------------------------------------------+
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "SAPI.h"
#include "ext/standard/php_var.h"
#include "php.h"
#include "php_ini.h"
#include "php_scandir.h"
#include "php_uc.h"
#include "storage.hpp"
#include "uc_arginfo.h"
#include "zend_smart_str.h"
#include <syslog.h>

ZEND_DECLARE_MODULE_GLOBALS(uc)

static zend_function_entry uc_functions[] = {
    // clang-format off
    PHP_FE(uc_test, NULL)
    PHP_FE(uc_clear_cache, arginfo_uc_clear_cache)
    PHP_FE(uc_store, arginfo_uc_store)
    PHP_FE(uc_size, arginfo_uc_size)
    PHP_FE(uc_inc, arginfo_uc_inc)
    PHP_FE(uc_dec, arginfo_uc_inc)
    PHP_FE(uc_cas, arginfo_uc_cas)
    PHP_FE(uc_add, arginfo_uc_store)
    PHP_FE(uc_fetch, arginfo_uc_fetch)
    PHP_FE(uc_delete, arginfo_uc_delete)
    PHP_FE(uc_exists, arginfo_uc_exists)
    PHP_FE(uc_dump, arginfo_uc_dump)
    { NULL, NULL, NULL }
    // clang-format on
};

zend_module_entry uc_module_entry = {
    STANDARD_MODULE_HEADER, PHP_UC_EXTNAME, uc_functions, PHP_MINIT(uc),  PHP_MSHUTDOWN(uc),
    PHP_RINIT(uc),          NULL,           NULL,         PHP_UC_VERSION, STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_UC
ZEND_GET_MODULE(uc)
#endif

PHP_INI_BEGIN()
STD_PHP_INI_BOOLEAN("uc.enabled", "1", PHP_INI_SYSTEM, OnUpdateBool, enabled, zend_uc_globals, uc_globals)
STD_PHP_INI_ENTRY("uc.size_in_mb", "32", PHP_INI_SYSTEM, OnUpdateLong, size_in_mb, zend_uc_globals, uc_globals)
STD_PHP_INI_ENTRY(
  "uc.preload_path", (char*) NULL, PHP_INI_SYSTEM, OnUpdateString, preload_path, zend_uc_globals, uc_globals)
PHP_INI_END()

static void
php_uc_init_globals(zend_uc_globals* uc_globals)
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

    int retval;

    UC_G(storage) = uc_storage_init(UC_G(size_in_mb) * 1024 * 1024);
    if (NULL == UC_G(storage)) {
        return FAILURE;
    }

    if (UC_G(preload_path)) {
        // uc_cache_preload(UC_G(preload_path));
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Unimplemented: uc.preload_path");
    }

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
/* {{{ proto void uc_clear_cache() */
PHP_FUNCTION(uc_clear_cache)
{
    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }
    uc_storage_clear(UC_G(storage));
    RETURN_TRUE;
}
/* }}} */

/* {{{ uc_time */
time_t
uc_time()
{
    return (time_t) sapi_get_request_time();
}
/* }}} */

/* {{{ uc_cache_store */
int
uc_cache_store(const zend_string* key, const zval* val, const size_t ttl, const zend_bool exclusive)
{
    char* err;
    int success       = 0;
    time_t expiration = 0;

    if (ttl > 0) {
        expiration = time(0) + ttl;
    }

    return uc_storage_store(UC_G(storage), key, val, expiration, exclusive);
}
/* }}} */

/* {{{ uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const zend_bool exclusive)
 */
static void
uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const zend_bool exclusive)
{
    int retval;
    zval* key     = NULL;
    zval* val     = NULL;
    zend_long ttl = 0L;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|zl", &key, &val, &ttl) == FAILURE) {
        return;
    }

    if (!key || !UC_G(enabled)) {
        /* cannot work without key */
        RETURN_FALSE;
    }

    if (Z_TYPE_P(key) == IS_ARRAY) {
        zval* hentry;
        zend_string* hkey;
        zend_ulong hkey_idx;

        HashPosition hpos;
        HashTable* hash = Z_ARRVAL_P(key);

        /* note: only indicative of error */
        array_init(return_value);
        zend_hash_internal_pointer_reset_ex(hash, &hpos);
        while ((hentry = zend_hash_get_current_data_ex(hash, &hpos))) {
            if (zend_hash_get_current_key_ex(hash, &hkey, &hkey_idx, &hpos) == HASH_KEY_IS_STRING) {
                if (!uc_cache_store(hkey, hentry, (uint32_t) ttl, exclusive)) {
                    add_assoc_long_ex(return_value, hkey->val, hkey->len, -1); /* -1: insertion error */
                }
            } else {
                add_index_long(return_value, hkey_idx, -1); /* -1: insertion error */
            }
            zend_hash_move_forward_ex(hash, &hpos);
        }
        return;
    } else {
        if (Z_TYPE_P(key) == IS_STRING) {
            if (!val) {
                /* nothing to store */
                RETURN_FALSE;
            }
            /* return true on success */
            if (uc_cache_store(Z_STR_P(key), val, (uint32_t) ttl, exclusive)) {
                RETURN_TRUE;
            }
        } else {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "uc_store() expects key parameter to be a string or an array of key/value pairs.");
        }
    }

    /* default */
    RETURN_FALSE;
}
/* }}} */

/* {{{ proto int uc_store(mixed key, mixed var [, long ttl ])
 */
PHP_FUNCTION(uc_store)
{
    uc_store_helper(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}
/* }}} */

/* {{{ proto int uc_add(mixed key, mixed var [, long ttl ])
 */
PHP_FUNCTION(uc_add)
{
    uc_store_helper(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}
/* }}} */

/* {{{ proto long apc_inc(string key [, long step [, bool& success]])
 */
PHP_FUNCTION(uc_inc)
{
    zend_string* key;
    zend_long step = 1;
    zval* success  = NULL;
    zval_and_success ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|lz", &key, &step, &success) == FAILURE) {
        return;
    }

    if (success) {
        ZVAL_DEREF(success);
        zval_ptr_dtor(success);
        ZVAL_FALSE(success);
    }

    ret = uc_storage_increment(UC_G(storage), key, step);

    if (success && ret.success) {
        ZVAL_TRUE(success);
    }

    RETURN_ZVAL(&ret.val, 1, 1);
}
/* }}} */

/* {{{ proto long apc_dec(string key [, long step [, bool& success]])
 */
PHP_FUNCTION(uc_dec)
{
    zend_string* key;
    zend_long step = 1;
    zval* success  = NULL;
    zval_and_success ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|lz", &key, &step, &success) == FAILURE) {
        return;
    }

    if (success) {
        ZVAL_DEREF(success);
        zval_ptr_dtor(success);
        ZVAL_FALSE(success);
    }

    ret = uc_storage_increment(UC_G(storage), key, -step);

    if (success && ret.success) {
        ZVAL_TRUE(success);
    }

    RETURN_ZVAL(&ret.val, 1, 1);
}
/* }}} */

/* {{{ proto int apc_cas(string key, int old, int new)
 */
PHP_FUNCTION(uc_cas)
{
    char* err;
    zend_string* key;
    zend_long vals[2];
    zval* new_val;
    zend_bool success;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sll", &key, &vals[0], &vals[1]) == FAILURE) {
        return;
    }

    success = uc_storage_cas(UC_G(storage), key, vals[1], vals[0]);

    if (success) {
        RETURN_TRUE;
    }

    RETURN_FALSE;
}
/* }}} */

/* {{{ uc_cache_size */
PHP_FUNCTION(uc_size)
{
    size_t size = uc_storage_size(UC_G(storage));
    RETURN_LONG(size);
}
/* }}} */

/* {{{ uc_dump */
PHP_FUNCTION(uc_dump)
{
    uc_storage_dump(UC_G(storage));
}
/* }}} */

/* {{{ uc_cache_fetch */
zval_and_success
uc_cache_fetch(const zend_string* key, const time_t t)
{
    zval_and_success ret;
    ret = uc_storage_get(UC_G(storage), key);
    return ret;
}
/* }}} */

/* {{{ proto mixed uc_fetch(mixed key[, bool &success])
 */
PHP_FUNCTION(uc_fetch)
{
    zval* key;
    zval* success = NULL;
    time_t t;
    zval_and_success ret;

    if (!UC_G(enabled)) {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|z", &key, &success) == FAILURE) {
        return;
    }

    t = uc_time();

    if (success) {
        ZVAL_DEREF(success);
        zval_ptr_dtor(success);
        ZVAL_FALSE(success);
    }

    if (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_ARRAY) {
        convert_to_string(key);
    }

    if (Z_TYPE_P(key) == IS_ARRAY || (Z_TYPE_P(key) == IS_STRING && Z_STRLEN_P(key) > 0)) {
        if (Z_TYPE_P(key) == IS_STRING) {
            ret = uc_cache_fetch(Z_STR_P(key), t);
            if (success && ret.success) {
                ZVAL_TRUE(success);
            }
            RETURN_ZVAL(&(ret.val), 0, 1);
        } else if (Z_TYPE_P(key) == IS_ARRAY) {
            HashPosition hpos;
            zval* hentry;
            zval retarray;

            array_init(&retarray);
            zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(key), &hpos);
            while ((hentry = zend_hash_get_current_data_ex(Z_ARRVAL_P(key), &hpos))) {
                if (Z_TYPE_P(hentry) == IS_STRING) {
                    zval_and_success result_entry = uc_cache_fetch(Z_STR_P(hentry), t);
                    if (result_entry.success) {
                        add_assoc_zval(&retarray, Z_STRVAL_P(hentry), &(result_entry.val));
                    }
                } else {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_fetch() expects a string or array of strings.");
                }

                zend_hash_move_forward_ex(Z_ARRVAL_P(key), &hpos);
            }

            if (success) {
                ZVAL_TRUE(success);
            }
            RETURN_ZVAL(&retarray, 0, 1);
        }
    }

    php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_fetch() expects a string or array of strings.");
    RETURN_FALSE;
}
/* }}} */

/* {{{ uc_cache_delete */
zend_bool
uc_cache_delete(const zend_string* key)
{
    return uc_storage_delete(UC_G(storage), key);
}
/* }}} */

/* {{{ proto mixed uc_delete(mixed keys)
 */
PHP_FUNCTION(uc_delete)
{
    zval* keys;

    if (!UC_G(enabled)) {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &keys) == FAILURE) {
        return;
    }

    if (Z_TYPE_P(keys) == IS_STRING) {
        if (!Z_STRLEN_P(keys)) {
            RETURN_FALSE;
        }

        if (uc_cache_delete(Z_STR_P(keys))) {
            RETURN_TRUE;
        } else {
            RETURN_FALSE;
        }

    } else if (Z_TYPE_P(keys) == IS_ARRAY) {
        HashPosition hpos;
        zval* hentry;

        array_init(return_value);
        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(keys), &hpos);

        while ((hentry = zend_hash_get_current_data_ex(Z_ARRVAL_P(keys), &hpos))) {
            if (Z_TYPE_P(hentry) != IS_STRING) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                 "uc_delete() expects a string, array of strings, or UCIterator instance.");
                add_next_index_zval(return_value, hentry);
                Z_ADDREF_P(hentry);
            } else if (uc_cache_delete(Z_STR_P(hentry)) != 1) {
                add_next_index_zval(return_value, hentry);
                Z_ADDREF_P(hentry);
            }
            zend_hash_move_forward_ex(Z_ARRVAL_P(keys), &hpos);
        }
    } else if (Z_TYPE_P(keys) == IS_OBJECT) {
        // @TODO: Add iterator support.
        // if (uc_iterator_delete(keys)) {
        //    RETURN_TRUE;
        //} else {
        RETURN_FALSE;
        //}
    } else {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "uc_delete() expects a string, array of strings, or UCIterator instance.");
    }
}
/* }}} */

/* {{{ proto mixed apc_exists(mixed key)
 */
PHP_FUNCTION(uc_exists)
{
    zend_bool found;
    zval* key;
    time_t t;

    if (!UC_G(enabled)) {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &key) == FAILURE) {
        return;
    }

    // @TODO: Make configurable.
    t = time(0);

    if (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_ARRAY) {
        convert_to_string(key);
    }

    if (Z_TYPE_P(key) == IS_STRING) {
        if (Z_STRLEN_P(key)) {
            found = uc_storage_exists(UC_G(storage), Z_STR_P(key));
            if (found) {
                RETURN_TRUE;
            } else {
                RETURN_FALSE;
            }
        }
    } else if (Z_TYPE_P(key) == IS_ARRAY) {
        HashPosition hpos;
        zval* hentry;

        array_init(return_value);

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(key), &hpos);
        while ((hentry = zend_hash_get_current_data_ex(Z_ARRVAL_P(key), &hpos))) {
            if (Z_TYPE_P(hentry) == IS_STRING) {
                found = uc_storage_exists(UC_G(storage), Z_STR_P(hentry));
                if (found) {
                    add_assoc_bool(return_value, Z_STRVAL_P(hentry), 1);
                }
            } else {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_exists() expects a string or array of strings.");
            }

            /* don't set values we didn't find */
            zend_hash_move_forward_ex(Z_ARRVAL_P(key), &hpos);
        }

        return;
    } else {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_exists() expects a string or array of strings.");
    }

    RETURN_FALSE;
}
/* }}} */

// UCIterator
