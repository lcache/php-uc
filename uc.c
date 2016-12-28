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
#include "uc_arginfo.h"
#include "zend_smart_str.h"
#include "ext/standard/php_var.h"
#include "SAPI.h"

ZEND_DECLARE_MODULE_GLOBALS(uc)

static zend_function_entry uc_functions[] = {
    PHP_FE(uc_test, NULL)
    PHP_FE(uc_compact, NULL)
    PHP_FE(uc_clear_cache, arginfo_uc_clear_cache)
    PHP_FE(uc_store, arginfo_uc_store)
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
PHP_INI_END()

#define UC_MAGIC 19840311

typedef enum {
    kPut = 0,
    kInc = 1
} uc_operation_t;

typedef struct {
    long counter_delta;
    size_t ttl;
    time_t created;
    time_t modified;
    uc_operation_t op;
    size_t version;
    uint32_t magic;
} uc_metadata_t;

static void php_uc_init_globals(zend_uc_globals *uc_globals)
{
}

PHP_RINIT_FUNCTION(uc)
{
    return SUCCESS;
}

zend_bool uc_read_metadata(const char* val, size_t val_len, uc_metadata_t* meta) {
    // @TODO: Move errors to a *err parameter.
    if (val_len < sizeof(*meta)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Value (len %lu) is shorter than expected metadata (len %lu).", val_len, sizeof(*meta));
        return 0;
    }

    // Copy metadata into the struct.
    memcpy(meta, (void *) (val + val_len - sizeof(*meta)), sizeof(*meta));

    if (meta->magic != UC_MAGIC) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Magic number (%lu) does not match expected value (%lu).", meta->magic, UC_MAGIC);
        return 0;
    }

    if (meta->version > 1) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Metadata (version %lu) exceeds known versions.", meta->version);
        return 0;
    }
    return 1;
}

zend_bool uc_metadata_is_fresh(uc_metadata_t meta, time_t now) {
    // Entries with no TTL are always fresh.
    if (meta.ttl == 0) {
        return 1;
    }

    // Entries with a TTL of 1984 should go down the memory hole.
    if (meta.ttl == 1984) {
        return 0;
    }

    // Check the time elapsed since last modification.
    if (meta.modified + meta.ttl >= now) {
        return 1;
    }

    return 0;
}

static void uc_filter_destory(void* arg) {}
static const char* uc_filter_name(void* arg) { return "uc"; }
static unsigned char uc_filter_filter(void* arg, int level, const char* key, size_t key_length, const char* existing_value, size_t value_length, char** new_value, size_t* new_value_length, unsigned char* value_changed) {
    uc_metadata_t meta;
    zend_bool status_ok;

    status_ok = uc_read_metadata(existing_value, value_length, &meta);
    // Keep entries on parsing failure.
    if (!status_ok) {
        return 0;
    }

    // Prune stale entries with TTLs.
    if (!uc_metadata_is_fresh(meta, time(NULL))) {
        return 1;
    }

    return 0;
}

PHP_MINIT_FUNCTION(uc)
{
    ZEND_INIT_MODULE_GLOBALS(uc, php_uc_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    char* err = NULL;

    rocksdb_options_t* db_options = rocksdb_options_create();
    rocksdb_options_t* cf_options = rocksdb_options_create();
    rocksdb_compactionfilter_t* cfilter;
    const char* cf_names[1] = {"default"};
    const rocksdb_options_t* cf_opts[1] = {cf_options};
    rocksdb_column_family_handle_t* cfs_h[1];

    rocksdb_options_set_create_if_missing(db_options, 1);
    rocksdb_options_set_create_missing_column_families(db_options, 1);

    // Apply the TTL-based compaction filter.
    cfilter = rocksdb_compactionfilter_create(NULL, uc_filter_destory, uc_filter_filter, uc_filter_name);
    rocksdb_options_set_compaction_filter(db_options, cfilter);

    UC_G(db_h) = rocksdb_open_column_families(db_options, UC_G(storage_directory), 1, cf_names, cf_opts, cfs_h, &err);
    UC_G(cf_h) = cfs_h[0];

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
    // rocksdb_compactionfilter_destroy
    // rocksdb_column_family_handle_destroy
    // rocksdb_close

    return SUCCESS;
}

PHP_FUNCTION(uc_test)
{
    RETURN_STRING("UC Test");
}

/* {{{ proto void uc_compact() */
PHP_FUNCTION(uc_compact)
{
    rocksdb_compact_range_cf(UC_G(db_h), UC_G(cf_h), NULL, 0, NULL, 0);
    RETURN_TRUE;
}
/* }}} */

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
    rocksdb_writebatch_delete_range_cf(wb, UC_G(cf_h), NULL, 0, NULL, 0);
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

void uc_print_metadata(const char *val, size_t val_len) {
    uc_metadata_t meta;
    uc_read_metadata(val, val_len, &meta);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "OP:  %d", meta.op);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "TS:  %lu", meta.modified);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "TTL: %lu", meta.ttl);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "VER: %lu", meta.version);
}

/* {{{ uc_time */
time_t uc_time() {
  return (time_t) sapi_get_request_time();
}
/* }}} */

zend_bool uc_append_metadata(smart_str* val, uc_metadata_t meta) {
    meta.version = 1;
    meta.magic = UC_MAGIC;
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Before (%lu): %s", ZSTR_LEN(val->s), ZSTR_VAL(val->s));
    smart_str_appendl(val, (const char *) &meta, sizeof(meta));
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "After (%lu): %s", ZSTR_LEN(val->s), ZSTR_VAL(val->s));
    uc_print_metadata(ZSTR_VAL(val->s), ZSTR_LEN(val->s));
    return 1;
}

zend_bool uc_strip_metadata(const char* val, size_t *val_len, uc_metadata_t* meta) {
    zend_bool status;

    status = uc_read_metadata(val, *val_len, meta);
    if (!status) {
        return status;
    }

    val_len -= sizeof(*meta);

    return 1;
}

/* {{{ uc_cache_store */
zend_bool uc_cache_store(zend_string *key, const zval *val, const size_t ttl, const zend_bool exclusive) {
    // @TODO: Add support for exclusive mode.
    zend_bool status;

    // Serialize the incoming value: val -> val_s
    smart_str val_s = {0};
    php_serialize_data_t var_hash;
    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&val_s, (zval*) val, &var_hash);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);

    // Append metadata.
    uc_metadata_t meta = {0};
    meta.modified = uc_time();
    meta.created = meta.modified;
    meta.ttl = ttl;
    meta.op = kPut;
    status = uc_append_metadata(&val_s, meta);
    if (!status) {
        return status;
    }

    // Create a batch that writes the desired CF and deletes from the others.
    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Next: rocksdb_writebatch_put_cf: %s", ZSTR_VAL(val_s.s));
    rocksdb_writebatch_put_cf(wb, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key), ZSTR_VAL(val_s.s), ZSTR_LEN(val_s.s));

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Next: rocksdb_writeoptions_create");

    // Write the batch to storage.
    char *err = NULL;
    rocksdb_writeoptions_t* woptions;
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
    char* err = NULL;
    rocksdb_readoptions_t* roptions;
    rocksdb_column_family_handle_t* cf_h;
    uc_metadata_t meta;
    char* val_s;
    size_t val_s_len;
    zend_bool status;

    roptions = rocksdb_readoptions_create();
    val_s = rocksdb_get_cf(UC_G(db_h), roptions, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key), &val_s_len, &err);
    rocksdb_readoptions_destroy(roptions);

    // A NULL is a miss.
    if (val_s == NULL) {
        ZVAL_NULL(*dst);
        return 0;
    }

    // Parse metadata.
    status = uc_strip_metadata(val_s, &val_s_len, &meta);
    if (!status) {
        return status;
    }

    // Miss on stale data. No need to explicitly delete;
    // the next compaction will handle deleting stale data.
    if (!uc_metadata_is_fresh(meta, uc_time())) {
        return 0;
    }

    const unsigned char *tmp = (unsigned char *) val_s;
    php_unserialize_data_t var_hash;
    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    if(!php_var_unserialize(*dst, &tmp, (unsigned char *) val_s + val_s_len, &var_hash)) {
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        php_error_docref(NULL, E_NOTICE, "Error at offset %ld of %ld bytes", (zend_long)(tmp - (unsigned char *) val_s), (zend_long)val_s_len);
        rocksdb_free(val_s);
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
    rocksdb_writebatch_delete_cf(wb, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key));
    woptions = rocksdb_writeoptions_create();
    rocksdb_write(UC_G(db_h), woptions, wb, &err);
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
// uc_inc
// uc_dec
// uc_cas

