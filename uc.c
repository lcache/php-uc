/*
  +----------------------------------------------------------------------+
  | APC                                                                  |
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
  | Authors: davidstrauss, krakjoe                                       |
  +----------------------------------------------------------------------+
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_uc.h"
#include "uc_arginfo.h"
#include "zend_smart_str.h"
#include "ext/standard/php_var.h"
#include "SAPI.h"

#define TTL_SHORT 3600
#define TTL_LONG 86400
#define CF_COUNT 3

ZEND_DECLARE_MODULE_GLOBALS(uc)

static zend_function_entry uc_functions[] = {
    PHP_FE(uc_test, NULL)
    PHP_FE(uc_clear_cache, arginfo_uc_clear_cache)
    PHP_FE(uc_store, arginfo_uc_store)
    PHP_FE(uc_fetch, arginfo_uc_fetch)
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
    STD_PHP_INI_BOOLEAN("uc.enabled", "1", PHP_INI_SYSTEM, OnUpdateBool, enabled, zend_uc_globals, uc_globals)
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

    rocksdb_options_t *db_options = rocksdb_options_create();
    rocksdb_options_t* cf_options = rocksdb_options_create();

    char *err = NULL;

    const char* cf_names[CF_COUNT] = {"default", "short", "long"};
    const rocksdb_options_t* cf_opts[CF_COUNT] = {cf_options, cf_options, cf_options};
    const int ttls[CF_COUNT] = {0, TTL_SHORT, TTL_LONG};

    rocksdb_options_set_create_if_missing(db_options, 1);
    rocksdb_options_set_create_missing_column_families(db_options, 1);

    UC_G(db_h) = rocksdb_open_column_families_with_ttl(db_options, UC_G(storage_directory), CF_COUNT, cf_names, cf_opts, UC_G(cfs_h), ttls, &err);

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Opening the user cache database failed: %s", err);
        return FAILURE;
    }

    rocksdb_free(err);
    err = NULL;

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(uc)
{
    UNREGISTER_INI_ENTRIES();

    // @TODO: Properly free memory for CFs and DB.
    // rocksdb_column_family_handle_destroy
    // rocksdb_close

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

    char *err = NULL;
    rocksdb_writeoptions_t* woptions;

    // @TODO: Optimize to use rocksdb_delete_file_in_range_cf() first.

    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    for (int i = 0; i < CF_COUNT; i++) {
      rocksdb_writebatch_delete_range_cf(wb, UC_G(cfs_h)[i], "", 0, "", 0);
    }
    woptions = rocksdb_writeoptions_create();
    rocksdb_writeoptions_set_sync(woptions, 1);
    rocksdb_write(UC_G(db_h), woptions, wb, &err);
    rocksdb_writeoptions_destroy(woptions);

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to clear the user cache database: %s", err);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}
/* }}} */

/* {{{ uc_time */
time_t uc_time() {
  return (time_t) sapi_get_request_time();
}
/* }}} */

/* {{{ uc_cache_store */
zend_bool uc_cache_store(zend_string *key, const zval *val, const int32_t ttl, const zend_bool exclusive) {
    // @TODO: Add support for exclusive mode.

    char *err = NULL;
    rocksdb_writeoptions_t* woptions;
    smart_str val_s = {0};
    size_t cf_idx;

    // Serialize the incoming value: val -> val_s
    php_serialize_data_t var_hash;
    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&val_s, (zval*) val, &var_hash);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);

    // Choose a column family.
    if (ttl == 0) {
      cf_idx = 0;
    } else if (ttl < TTL_LONG) {
      cf_idx = 1;
    } else {
      // Even TTLs longer than TTL_LONG go into the last column family.
      cf_idx = 2;
    }

    // Create a batch that writes the desired CF and deletes from the others.
    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    for (size_t i = 0; i < CF_COUNT; i++) {
      if (i == cf_idx) {
        rocksdb_writebatch_put_cf(wb, UC_G(cfs_h)[i], ZSTR_VAL(key), ZSTR_LEN(key), ZSTR_VAL(val_s.s), ZSTR_LEN(val_s.s));
      } else {
        rocksdb_writebatch_delete_cf(wb, UC_G(cfs_h)[i], ZSTR_VAL(key), ZSTR_LEN(key));
      }
    }

    // Write the batch to storage.
    woptions = rocksdb_writeoptions_create();
    rocksdb_write(UC_G(db_h), woptions, wb, &err);
    rocksdb_writeoptions_destroy(woptions);

    rocksdb_writebatch_destroy(wb);
    smart_str_free(&val_s);

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to store to user cache: %s", err);
        return 0;
    }

    return 1;
}
/* }}} */

/* {{{ uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const zend_bool exclusive)
 */
static void uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const zend_bool exclusive)
{
    // @TODO: Add RocksDB batch support for array writes.
    zval *key = NULL;
    zval *val = NULL;
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

            zval *hentry;
            zend_string *hkey;
            zend_ulong hkey_idx;

            HashPosition hpos;
            HashTable* hash = Z_ARRVAL_P(key);

            /* note: only indicative of error */
		    array_init(return_value);
		    zend_hash_internal_pointer_reset_ex(hash, &hpos);
		    while((hentry = zend_hash_get_current_data_ex(hash, &hpos))) {
		        if (zend_hash_get_current_key_ex(hash, &hkey, &hkey_idx, &hpos) == HASH_KEY_IS_STRING) {
		            if(!uc_cache_store(hkey, hentry, (uint32_t) ttl, exclusive)) {
		                add_assoc_long_ex(return_value, hkey->val, hkey->len, -1);  /* -1: insertion error */
		            }
		        } else {
		            add_index_long(return_value, hkey_idx, -1);  /* -1: insertion error */
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
    			if(uc_cache_store(Z_STR_P(key), val, (uint32_t) ttl, exclusive)) {
    	            RETURN_TRUE;
                }
    		} else {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_store expects key parameter to be a string or an array of key/value pairs.");
    		}
        }
	}

	/* default */
    RETURN_FALSE;
}
/* }}} */

/* {{{ proto int uc_store(mixed key, mixed var [, long ttl ])
 */
PHP_FUNCTION(uc_store) {
    uc_store_helper(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}
/* }}} */

/* {{{ proto int uc_add(mixed key, mixed var [, long ttl ])
 */
PHP_FUNCTION(uc_add) {
    uc_store_helper(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}
/* }}} */

/* {{{ uc_cache_fetch */
zend_bool uc_cache_fetch(zend_string *key, time_t t, zval **dst)
{
    char *err = NULL;
    rocksdb_readoptions_t* roptions;
    rocksdb_column_family_handle_t* cf_h;
    unsigned char* val_s;
    size_t val_s_len;

    roptions = rocksdb_readoptions_create();
    for (int i = 0; i < CF_COUNT; i++) {
        val_s = (unsigned char *) rocksdb_get_cf(UC_G(db_h), roptions, UC_G(cfs_h)[i], ZSTR_VAL(key), ZSTR_LEN(key), &val_s_len, &err);
        if (val_s) {
            break;
        }
    }
    rocksdb_readoptions_destroy(roptions);

    const unsigned char *tmp = val_s;

    php_unserialize_data_t var_hash;
    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    if(!php_var_unserialize(*dst, &tmp, val_s + val_s_len, &var_hash)) {
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        rocksdb_free(val_s);
        php_error_docref(NULL, E_NOTICE, "Error at offset %ld of %ld bytes", (zend_long)(tmp - val_s), (zend_long)val_s_len);
        ZVAL_NULL(*dst);
        return 0;
    }
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);

    rocksdb_free(val_s);
    return 1;
} /* }}} */


/* {{{ proto mixed uc_fetch(mixed key[, bool &success])
 */
PHP_FUNCTION(uc_fetch) {
    zval *key;
    zval *success = NULL;
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
			} else { ZVAL_BOOL(return_value, 0); }
		} else if (Z_TYPE_P(key) == IS_ARRAY) {
			HashPosition hpos;
			zval *hentry;
			zval result;

			array_init(&result);
			zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(key), &hpos);
			while((hentry = zend_hash_get_current_data_ex(Z_ARRVAL_P(key), &hpos))) {
			    if (Z_TYPE_P(hentry) == IS_STRING) {
					zval result_entry,
						*iresult = &result_entry;
					ZVAL_UNDEF(iresult);

					if (uc_cache_fetch(Z_STR_P(hentry), t, &iresult)) {
					    add_assoc_zval(&result, Z_STRVAL_P(hentry), &result_entry);
					}
			    } else {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_fetch expects a string or array of strings.");
				}

			    zend_hash_move_forward_ex(Z_ARRVAL_P(key), &hpos);
			}

			RETVAL_ZVAL(&result, 0, 1);

			if (success) {
				ZVAL_TRUE(success);
			}
		}
	} else {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_fetch expects a string or array of strings.");
		RETURN_FALSE;
	}
    return;
}
/* }}} */

// uc_delete
// UCIterator

// uc_inc
// uc_dec
// uc_cas

