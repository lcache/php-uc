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
    char* err;

    UC_G(storage) = uc_storage_init(UC_G(size_in_mb) * 1024 * 1024, &err);
    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_init: %s", err);
        uc_string_free(err);
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

    char* err = NULL;

    uc_storage_clear(UC_G(storage), &err);
    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_clear: %s", err);
        uc_string_free(err);
        RETURN_FALSE;
    }

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
uc_cache_store(zend_string* key, const zval* val, const size_t ttl, const zend_bool exclusive)
{
    char* err;
    int success       = 0;
    smart_str val_s   = { 0 };
    time_t expiration = 0;

    if (ttl > 0) {
        expiration = time(0) + ttl;
    }

    // @TODO: As for fetch, relocate this code to the storage layer.
    if (Z_TYPE_P(val) == IS_LONG) {
        success = uc_storage_store_long(UC_G(storage), ZSTR_VAL(key), ZSTR_LEN(key), Z_LVAL_P(val), expiration, exclusive, &err);
        if (err != NULL) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_store_long: %s", err);
            uc_string_free(err);
            return 0;
        }
    } else {
        php_serialize_data_t var_hash;
        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&val_s, (zval*) val, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        success = uc_storage_store(UC_G(storage), ZSTR_VAL(key), ZSTR_LEN(key), ZSTR_VAL(val_s.s), ZSTR_LEN(val_s.s),
                                   expiration, exclusive, &err);
        if (err != NULL) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_store: %s", err);
            uc_string_free(err);
            smart_str_free(&val_s);
            return 0;
        }
        smart_str_free(&val_s);
    }

    return success;
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

    /* keep it tidy */
    {
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
    int retval;
    char* err;
    zend_string* key;
    zend_long step = 1;
    zval* success  = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|lz", &key, &step, &success) == FAILURE) {
        return;
    }

    if (success) {
        ZVAL_DEREF(success);
        zval_ptr_dtor(success);
    }

    retval = uc_storage_increment(UC_G(storage), ZSTR_VAL(key), ZSTR_LEN(key), &step, &err);
    if (retval) {
        if (success) {
            ZVAL_TRUE(success);
        }
        RETURN_LONG(step);
    }

    if (success) {
        ZVAL_FALSE(success);
    }

    RETURN_FALSE;
}
/* }}} */

/* {{{ proto long apc_dec(string key [, long step [, bool& success]])
 */
PHP_FUNCTION(uc_dec)
{
    int retval;
    char* err;
    zend_string* key;
    zend_long step = 1;
    zval* success  = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|lz", &key, &step, &success) == FAILURE) {
        return;
    }

    if (success) {
        ZVAL_DEREF(success);
        zval_ptr_dtor(success);
    }

    step *= -1;

    retval = uc_storage_increment(UC_G(storage), ZSTR_VAL(key), ZSTR_LEN(key), &step, &err);
    if (retval) {
        if (success) {
            ZVAL_TRUE(success);
        }
        RETURN_LONG(step);
    }

    if (success) {
        ZVAL_FALSE(success);
    }

    RETURN_FALSE;
}
/* }}} */

/* {{{ proto int apc_cas(string key, int old, int new)
 */
PHP_FUNCTION(uc_cas)
{
    int retval = 0;
    zend_string* key;
    zend_long vals[2];
    zval* new_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sll", &key, &vals[0], &vals[1]) == FAILURE) {
        return;
    }

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cas 1");

    // retval = uc_cache_store(key, NULL, 0, kCAS, vals[0], vals[1]);
    if (0 == retval) {
        RETURN_TRUE;
    }

    RETURN_FALSE;
}
/* }}} */

/* {{{ uc_cache_size */
PHP_FUNCTION(uc_size)
{
    char* err;
    size_t size = uc_storage_size(UC_G(storage), &err);
    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_size: %s", err);
        uc_string_free(err);
        size = 0;
    }
    RETURN_LONG(size);
}
/* }}} */

/* {{{ uc_dump */
PHP_FUNCTION(uc_dump)
{
    char* err;
    uc_storage_dump(UC_G(storage), &err);
    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_dump: %s", err);
        uc_string_free(err);
        return;
    }
}
/* }}} */

/* {{{ uc_cache_fetch */
int
uc_cache_fetch(zend_string* key, time_t t, zval** dst)
{
    char* err;
    int success;
    success = uc_storage_get(UC_G(storage), ZSTR_VAL(key), ZSTR_LEN(key), dst, &err);
    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_get: %s", err);
        uc_string_free(err);
        return FAILURE;
    }
    return success;
}
/* }}} */

/* {{{ proto mixed uc_fetch(mixed key[, bool &success])
 */
PHP_FUNCTION(uc_fetch)
{
    zval* key;
    zval* success = NULL;
    time_t t;

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
            if (uc_cache_fetch(Z_STR_P(key), t, &return_value)) {
                if (success) {
                    ZVAL_TRUE(success);
                }
            } else {
                ZVAL_BOOL(return_value, 0);
            }
        } else if (Z_TYPE_P(key) == IS_ARRAY) {
            HashPosition hpos;
            zval* hentry;
            zval result;

            array_init(&result);
            zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(key), &hpos);
            while ((hentry = zend_hash_get_current_data_ex(Z_ARRVAL_P(key), &hpos))) {
                if (Z_TYPE_P(hentry) == IS_STRING) {
                    zval result_entry, *iresult = &result_entry;
                    ZVAL_UNDEF(iresult);

                    if (uc_cache_fetch(Z_STR_P(hentry), t, &iresult)) {
                        add_assoc_zval(&result, Z_STRVAL_P(hentry), &result_entry);
                    }
                } else {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_fetch() expects a string or array of strings.");
                }

                zend_hash_move_forward_ex(Z_ARRVAL_P(key), &hpos);
            }

            RETVAL_ZVAL(&result, 0, 1);

            if (success) {
                ZVAL_TRUE(success);
            }
        }
    } else {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_fetch() expects a string or array of strings.");
        RETURN_FALSE;
    }
    return;
}
/* }}} */

/* {{{ uc_cache_delete */
zend_bool
uc_cache_delete(zend_string* key)
{
    char* err;
    int retval = uc_storage_delete(UC_G(storage), ZSTR_VAL(key), ZSTR_LEN(key), &err);
    if (NULL != err) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_delete: %s", err);
        uc_string_free(err);
        return 0;
    }
    return retval;
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
    char* err;
    int retval;
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
            retval = uc_storage_exists(UC_G(storage), ZSTR_VAL(Z_STR_P(key)), ZSTR_LEN(Z_STR_P(key)), &err);
            if (err != NULL) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_exists: %s", err);
                uc_string_free(err);
                retval = 0;
            }
            if (retval) {
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
                retval = uc_storage_exists(UC_G(storage), ZSTR_VAL(Z_STR_P(hentry)), ZSTR_LEN(Z_STR_P(hentry)), &err);
                if (err != NULL) {
                    php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_storage_exists: %s", err);
                    uc_string_free(err);
                    retval = 0;
                }
                if (retval) {
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
