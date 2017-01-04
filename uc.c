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
  |          Rasmus Lerdorf <rasmus@php.net>                             |
  |          Daniel Cowgill <dcowgill@communityconnect.com>              |
  +----------------------------------------------------------------------+
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_uc.h"
#include "marshalling.h"
#include "persistence.h"
#include "uc_arginfo.h"
#include "zend_smart_str.h"
#include "ext/standard/php_var.h"
#include "SAPI.h"
#include <syslog.h>

ZEND_DECLARE_MODULE_GLOBALS(uc)

static zend_function_entry uc_functions[] = {
    PHP_FE(uc_test, NULL)
    PHP_FE(uc_compact, NULL)
    PHP_FE(uc_clear_cache, arginfo_uc_clear_cache)
    PHP_FE(uc_store, arginfo_uc_store)
    PHP_FE(uc_inc, arginfo_uc_inc)
    PHP_FE(uc_cas, arginfo_uc_cas)
    PHP_FE(uc_add, arginfo_uc_store)
    PHP_FE(uc_fetch, arginfo_uc_fetch)
    PHP_FE(uc_delete, arginfo_uc_delete)
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
    STD_PHP_INI_ENTRY("uc.concurrency", "16", PHP_INI_SYSTEM, OnUpdateLong, concurrency, zend_uc_globals, uc_globals)
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

    int retval;

    retval = uc_persistence_init(UC_G(storage_directory), &UC_G(persistence));
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_persistence_init: %s", strerror(retval));
        return FAILURE;
    }

    retval = uc_workers_init(&UC_G(persistence), UC_G(concurrency), &UC_G(pool));
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_workers_init: %s", strerror(retval));
        return FAILURE;
    }

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(uc)
{
    UNREGISTER_INI_ENTRIES();

    int retval;

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Stopping workers...");
    retval = uc_workers_destroy(UC_G(pool));
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_workers_destroy: %s", strerror(retval));
        return FAILURE;
    }

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Closing persistence...");
    retval = uc_persistence_destroy(&UC_G(persistence));
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_persistence_destroy: %s", strerror(retval));
        return FAILURE;
    }

    return SUCCESS;
}

PHP_FUNCTION(uc_test)
{
    RETURN_STRING("UC Test");
}

int uc_append_metadata(smart_str* val, uc_metadata_t meta) {
    uc_init_metadata(&meta);
    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Before (%lu): %s", ZSTR_LEN(val->s), ZSTR_VAL(val->s));
    smart_str_appendl(val, (const char *) &meta, sizeof(meta));
    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "After (%lu): %s", ZSTR_LEN(val->s), ZSTR_VAL(val->s));
    //uc_print_metadata(ZSTR_VAL(val->s), ZSTR_LEN(val->s));
    return 0;
}

/* {{{ proto void uc_compact() */
PHP_FUNCTION(uc_compact)
{
    // @TODO: Reimplement with workers.

    //rocksdb_compact_range_cf(UC_G(db_h), UC_G(cf_h), NULL, 0, NULL, 0);
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto void uc_clear_cache() */
PHP_FUNCTION(uc_clear_cache)
{
    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    //char *err = NULL;
    //rocksdb_writeoptions_t* woptions;

    // @TODO: Optimize to use rocksdb_delete_file_in_range_cf() first.

    //rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    //rocksdb_writebatch_delete_range_cf(wb, UC_G(cf_h), NULL, 0, NULL, 0);
    //woptions = rocksdb_writeoptions_create();
    //rocksdb_writeoptions_disable_WAL(woptions, 1);
    //rocksdb_write(UC_G(db_h), woptions, wb, &err);
    //rocksdb_writeoptions_destroy(woptions);

    //if (err != NULL) {
    //    php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to clear the user cache database: %s", err);
    //    RETURN_FALSE;
    //}

    RETURN_TRUE;
}
/* }}} */

/* {{{ uc_time */
time_t uc_time() {
  return (time_t) sapi_get_request_time();
}
/* }}} */

/* {{{ uc_cache_store */
int uc_cache_store(zend_string *key, const zval *val, const size_t ttl, const uc_operation_t op, const zend_long cas_value_or_inc, const zend_long new_cas_value) {
    int retval = 0;
    uc_metadata_t meta = {0};
    smart_str val_s = {0};

    meta.op = op;

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store");

    if (meta.op == kCAS || meta.op == kInc) {
        meta.cas_value_or_inc = cas_value_or_inc;
    }

    if (meta.op == kCAS) {
        meta.value = new_cas_value;
        meta.value_type = kLong;
    }
    else if (val == NULL) {
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kNone");
        meta.value_type = kNone;
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kNone 2");
    }
    else if (Z_TYPE_P(val) == IS_LONG) {
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kLong");
        meta.value_type = kLong;
        meta.value = Z_LVAL_P(val);
    } else {
        //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kSerialized");
        meta.value_type = kSerialized;
        php_serialize_data_t var_hash;
        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&val_s, (zval*) val, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
    }

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store 2");

    if (meta.op == kInc) {
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store kInc %ld", meta.cas_value_or_inc);
    }

    // Append other metadata.
    meta.modified = uc_time();
    meta.created = meta.modified;
    meta.ttl = ttl;
    retval = uc_append_metadata(&val_s, meta);
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "uc_cache_store: failed uc_append_metadata: %s", strerror(retval));
        smart_str_free(&val_s);
        return retval;
    }

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store 3");

    if (ZSTR_LEN(key) > MAX_KEY_LENGTH) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to store to user cache: key length %lu > %lu", ZSTR_LEN(key), MAX_KEY_LENGTH);
        smart_str_free(&val_s);
        return EINVAL;
    }
    if (ZSTR_LEN(val_s.s) > MAX_VALUE_SIZE) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to store to user cache: value size %lu > %lu", ZSTR_LEN(val_s.s), MAX_VALUE_SIZE);
        smart_str_free(&val_s);
        return EINVAL;
    }

    // Find a free worker.
    worker_t* available;
    retval = uc_workers_choose_and_lock(UC_G(pool), &available);
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_workers_choose_and_lock: %s", strerror(retval));
        smart_str_free(&val_s);
        return retval;
    }

    syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "uc_cache_store: worker %lu acquired for PID %d.", available->id, getpid());

    // Copy the write into memory visible to the worker.
    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Writing value size: %lu", ZSTR_LEN(val_s.s));
    memcpy(available->k, ZSTR_VAL(key), ZSTR_LEN(key));
    available->kl = ZSTR_LEN(key);
    memcpy(available->v, ZSTR_VAL(val_s.s), ZSTR_LEN(val_s.s));
    available->vl = ZSTR_LEN(val_s.s);
    available->m = meta;
    smart_str_free(&val_s);

    // Complete the RPC
    retval = uc_workers_complete_rpc(available);
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_workers_send_request: %s", strerror(retval));
        return EIO;
    }
    // @TODO: Read confirmation here?
    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Completed write on worker %lu", available->id);
    retval = uc_workers_unlock(available);
    if (0 != retval) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed uc_workers_unlock: %s", strerror(retval));
        return retval;
    }

    //syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_NOTICE), "Worker released: %lu", available->id);

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store 5");

    return 0;
}
/* }}} */

/* {{{ uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const zend_bool exclusive)
 */
static void uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const uc_operation_t op)
{
    int retval;
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
                    retval = uc_cache_store(hkey, hentry, (uint32_t) ttl, op, 0, 0);
		            if(0 != retval) {
                        php_error_docref(NULL TSRMLS_CC, E_ERROR, "uc_store insertion error: %s", strerror(retval));
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
                retval = uc_cache_store(Z_STR_P(key), val, (uint32_t) ttl, op, 0, 0);
    			if(0 == retval) {
    	            RETURN_TRUE;
                }
    		} else {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_store() expects key parameter to be a string or an array of key/value pairs.");
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
    uc_store_helper(INTERNAL_FUNCTION_PARAM_PASSTHRU, kPut);
}
/* }}} */

/* {{{ proto int uc_add(mixed key, mixed var [, long ttl ])
 */
PHP_FUNCTION(uc_add) {
    uc_store_helper(INTERNAL_FUNCTION_PARAM_PASSTHRU, kAdd);
}
/* }}} */

/* {{{ proto long apc_inc(string key [, long step [, bool& success]])
 */
PHP_FUNCTION(uc_inc) {
    int retval;
    zend_string *key;
    zend_long step = 1;
    zval *success = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|lz", &key, &step, &success) == FAILURE) {
        return;
    }

	if (success) {
		ZVAL_DEREF(success);
		zval_ptr_dtor(success);
	}

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_inc(%d)", step);
    retval = uc_cache_store(key, NULL, 0, kInc, step, 0);
    if (0 == retval) {
        if (success) {
			ZVAL_TRUE(success);
		}
    }

    if (success) {
		ZVAL_FALSE(success);
	}

    RETURN_FALSE;
}
/* }}} */

/* {{{ proto int apc_cas(string key, int old, int new)
 */
PHP_FUNCTION(uc_cas) {
    int retval;
    zend_string *key;
    zend_long vals[2];
    zval *new_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sll", &key, &vals[0], &vals[1]) == FAILURE) {
        return;
    }

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cas 1");

    retval = uc_cache_store(key, NULL, 0, kCAS, vals[0], vals[1]);
    if (0 == retval) {
		RETURN_TRUE;
	}

    RETURN_FALSE;
}
/* }}} */

/* {{{ uc_cache_fetch */
zend_bool uc_cache_fetch(zend_string *key, time_t t, zval **dst)
{
    char* err = NULL;
    rocksdb_readoptions_t* roptions;
    rocksdb_column_family_handle_t* cf_h;
    uc_metadata_t meta;
    char* val_s;
    size_t val_s_len;
    zend_bool status_ok = 0;

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_fetch");

    roptions = rocksdb_readoptions_create();
    val_s = rocksdb_get_cf(UC_G(persistence).db_h, roptions, UC_G(persistence).cf_h, ZSTR_VAL(key), ZSTR_LEN(key), &val_s_len, &err);
    rocksdb_readoptions_destroy(roptions);

    // A NULL is a miss.
    if (val_s == NULL) {
        goto cleanup;
    }

    // Parse metadata.
    status_ok = uc_strip_metadata(val_s, &val_s_len, &meta);
    if (!status_ok) {
        php_error_docref(NULL, E_WARNING, "Error parsing metadata.");
        goto cleanup;
    }

    // Miss on stale data. No need to explicitly delete;
    // the next compaction will handle deleting stale data.
    if (!uc_metadata_is_fresh(meta, uc_time())) {
        goto cleanup;
    }

    if (meta.value_type == kLong) {
        ZVAL_LONG(*dst, meta.value);
    }
    else if (meta.value_type == kSerialized) {
        const unsigned char *tmp = (unsigned char *) val_s;
        php_unserialize_data_t var_hash;
        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        if(!php_var_unserialize(*dst, &tmp, (unsigned char *) val_s + val_s_len, &var_hash)) {
            PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
            php_error_docref(NULL, E_WARNING, "Error unserializing at offset %ld of %ld bytes", (zend_long)(tmp - (unsigned char *) val_s), (zend_long)val_s_len);
            goto cleanup;
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    } else {
        php_error_docref(NULL, E_WARNING, "Unknown value type: %lu", meta.value_type);
        goto cleanup;
    }

    status_ok = 1;

cleanup:
    rocksdb_free(val_s);
    if (!status_ok) {
        ZVAL_NULL(*dst);
    }
    return status_ok;
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
zend_bool uc_cache_delete(zend_string *key)
{
    char *err = NULL;
    rocksdb_writeoptions_t* woptions;

    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    rocksdb_writebatch_delete_cf(wb, UC_G(persistence).cf_h, ZSTR_VAL(key), ZSTR_LEN(key));
    woptions = rocksdb_writeoptions_create();
    //rocksdb_writeoptions_disable_WAL(woptions, 1);
    rocksdb_write(UC_G(persistence).db_h, woptions, wb, &err);
    rocksdb_writeoptions_destroy(woptions);
    rocksdb_writebatch_destroy(wb);

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to delete from user cache: %s", err);
        return 0;
    }

    return 1;
}
/* }}} */


/* {{{ proto mixed uc_delete(mixed keys)
 */
PHP_FUNCTION(uc_delete) {
    zval *keys;

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
        zval *hentry;

        array_init(return_value);
        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(keys), &hpos);

        while ((hentry = zend_hash_get_current_data_ex(Z_ARRVAL_P(keys), &hpos))) {
            if (Z_TYPE_P(hentry) != IS_STRING) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_delete() expects a string, array of strings, or UCIterator instance.");
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
        //if (uc_iterator_delete(keys)) {
        //    RETURN_TRUE;
        //} else {
            RETURN_FALSE;
        //}
    } else {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "uc_delete() expects a string, array of strings, or UCIterator instance.");
    }
}
/* }}} */

// UCIterator

