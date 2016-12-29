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
PHP_INI_END()

#define UC_MAGIC 19840311

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
    zend_long value;
    zend_long cas_value_or_inc;
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

    if (meta->op == kCAS && meta->value_type != kLong) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Inc or CAS operation has non-long value type: %lu", meta->value_type);
        return 0;
    }

    if (meta->op == kInc || meta->op == kCAS || meta->value_type == kNone) {
        if (val_len > sizeof(*meta)) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "Inc or CAS operation has extra bytes: %lu", val_len - sizeof(*meta));
            return 0;
        }
    }

    return 1;
}

void uc_print_metadata(const char *val, size_t val_len) {
    uc_metadata_t meta;
    uc_read_metadata(val, val_len, &meta);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "OP:  %d", meta.op);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "TS:  %lu", meta.modified);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "TTL: %lu", meta.ttl);
    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "VER: %lu", meta.version);
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
static const char* uc_filter_name(void* arg) { return "ttl"; }
static unsigned char uc_filter_filter(void* arg, int level, const char* key, size_t key_length, const char* existing_value, size_t value_length,
                                      char** new_value, size_t* new_value_length, unsigned char* value_changed) {
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

zend_bool uc_strip_metadata(const char* val, size_t *val_len, uc_metadata_t* meta) {
    zend_bool status;

    status = uc_read_metadata(val, *val_len, meta);
    if (!status) {
        return status;
    }

    *val_len -= sizeof(*meta);

    return 1;
}

zend_bool uc_append_metadata(smart_str* val, uc_metadata_t meta) {
    meta.version = 1;
    meta.magic = UC_MAGIC;
    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Before (%lu): %s", ZSTR_LEN(val->s), ZSTR_VAL(val->s));
    smart_str_appendl(val, (const char *) &meta, sizeof(meta));
    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "After (%lu): %s", ZSTR_LEN(val->s), ZSTR_VAL(val->s));
    //uc_print_metadata(ZSTR_VAL(val->s), ZSTR_LEN(val->s));
    return 1;
}

static void merge_op_destroy(void* arg) { }
static const char* merge_op_name(void* arg) {
    return "php-uc";
}
static char* merge_op_full_merge(void* arg, const char* key, size_t key_length, const char* existing_value, size_t existing_value_length, const char* const* operands_list, const size_t* operands_list_length, int num_operands, unsigned char* success, size_t* new_value_length) {
    uc_metadata_t meta = {0};
    uc_metadata_t merge_op_meta;
    zend_bool status_ok;
    const char* new_data;
    size_t new_data_len;

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Attempting full merge.");

    if (existing_value != NULL) {
        status_ok = uc_strip_metadata(existing_value, &existing_value_length, &meta);

        // Fail on invalid metadata.
        if (!status_ok) {
            *success = 0;
            return NULL;
        }
    }

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Loaded existing value.");

    // In the degenerate case of no operands, succeed and return the original value.
    *success = 1;
    new_data = existing_value;
    new_data_len = existing_value_length;

    // Iterate through the merge operands.
    for (size_t i = 0; i < num_operands; i++) {
        status_ok = uc_read_metadata(operands_list[i], operands_list_length[i], &merge_op_meta);

        // Fail on invalid metadata.
        if (!status_ok) {
            *success = 0;
            return NULL;
        }

        if (merge_op_meta.op == kInc) {
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kInc");

            meta.value_type = kLong;
            meta.value += merge_op_meta.cas_value_or_inc;
            meta.modified = merge_op_meta.modified;
            if (!meta.created) {
                meta.created = meta.modified;
            }

            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "New value: %ld", meta.value);

            // Counters never have anything outside metadata.
            new_data = NULL;
            new_data_len = 0;
        }
        else if (merge_op_meta.op == kAdd) {
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kAdd");

            if (existing_value == NULL) {
                meta = merge_op_meta;
                new_data = operands_list[i];
                new_data_len = operands_list_length[i];
            }
        }
        else if (merge_op_meta.op == kCAS) {
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "kCAS");

            // Compare. If the expected value is the current one, replace it.
            if (meta.value_type == kLong && meta.value == merge_op_meta.cas_value_or_inc) {
                meta = merge_op_meta;

                // CAS values never have anything outside metadata.
                new_data = NULL;
                new_data_len = 0;
            }
        } else {
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Unknown meta.op: %d", meta.op);

            // Unexpected value for meta.op.
            *success = 0;
            return NULL;
        }
    }

    // Combine the data and metadata into a single value.
    *new_value_length = new_data_len + sizeof(meta);
    char *new_value = malloc(*new_value_length);
    if (new_data) {
        memcpy(new_value, &new_data, new_data_len);
    }
    memcpy(new_value + new_data_len, &meta, sizeof(meta));

    return new_value;
}

static char* merge_op_partial_merge(void* arg, const char* key, size_t key_length, const char* const* operands_list, const size_t* operands_list_length, int num_operands, unsigned char* success, size_t* new_value_length) {

    uc_metadata_t meta;
    long net_counter_value = 0;
    zend_bool status_ok;

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Attempting partial merge.");

    for (size_t i = 0; i < num_operands; i++) {
        status_ok = uc_read_metadata(operands_list[i], operands_list_length[i], &meta);

        // Fail on invalid metadata.
        if (!status_ok) {
            *success = 0;
            return NULL;
        }

        // Fail on encountering anything other than increment operations.
        if (meta.op != kInc) {
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Non-kInc operation: failing partial merge");
            *success = 0;
            return NULL;
        }

        // Aggregate the counter data.
        net_counter_value += meta.value;
    }

    // Use the most recent metadata, but apply the net counter delta.
    meta.value = net_counter_value;

    // Allocate and return a fresh value.
    *new_value_length = sizeof(meta);
    *success = 1;
    char* result = (char*) malloc(sizeof(meta));
    memcpy(result, &meta, sizeof(meta));
    return result;
}

PHP_MINIT_FUNCTION(uc)
{
    ZEND_INIT_MODULE_GLOBALS(uc, php_uc_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    char* err = NULL;

    rocksdb_mergeoperator_t* merge_op;
    const char* cf_names[1] = {"default"};
    const rocksdb_options_t* cf_opts[1];
    rocksdb_column_family_handle_t* cfs_h[1];

    UC_G(db_options) = rocksdb_options_create();
    UC_G(cf_options) = rocksdb_options_create();
    cf_opts[0] = UC_G(cf_options);

    rocksdb_options_set_create_if_missing(UC_G(db_options), 1);
    rocksdb_options_set_use_adaptive_mutex(UC_G(db_options), 1);
    rocksdb_options_set_create_missing_column_families(UC_G(db_options), 1);
    rocksdb_options_set_compression(UC_G(db_options), /* rocksdb::kSnappyCompression */ 0x1);
    //rocksdb_options_set_info_log_level(UC_G(db_options), /* InfoLogLevel::DEBUG_LEVEL */ 2);

    // Apply the TTL-enforcing compaction filter.
    UC_G(cfilter) = rocksdb_compactionfilter_create(NULL, uc_filter_destory, uc_filter_filter, uc_filter_name);
    rocksdb_options_set_compaction_filter(UC_G(cf_options), UC_G(cfilter));

    // Apply the merge operator.
    merge_op = rocksdb_mergeoperator_create(NULL, merge_op_destroy, merge_op_full_merge, merge_op_partial_merge, NULL, merge_op_name);
    rocksdb_options_set_merge_operator(UC_G(cf_options), merge_op);

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "About to open the database.");

    UC_G(db_h) = rocksdb_open_column_families(UC_G(db_options), UC_G(storage_directory), 1, cf_names, cf_opts, cfs_h, &err);
    UC_G(cf_h) = cfs_h[0];

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Opening the user cache database failed: %s", err);
        return FAILURE;
    }

    // @TODO: Check for a clean shutdown. If not, clear the DB.

    rocksdb_free(err);
    err = NULL;

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(uc)
{
    UNREGISTER_INI_ENTRIES();

    // @TODO: Record that there's been a clean shutdown.

    rocksdb_column_family_handle_destroy(UC_G(cf_h));
    rocksdb_close(UC_G(db_h));
    rocksdb_options_destroy(UC_G(db_options));
    //rocksdb_compactionfilter_destroy(UC_G(cfilter));
    rocksdb_options_destroy(UC_G(cf_options));

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
    //rocksdb_writeoptions_disable_WAL(woptions, 1);
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
zend_bool uc_cache_store(zend_string *key, const zval *val, const size_t ttl, const uc_operation_t op, const zend_long cas_value_or_inc, const zend_long new_cas_value) {
    zend_bool status;
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
    status = uc_append_metadata(&val_s, meta);
    if (!status) {
        return status;
    }

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store 3");

    // Generate the write batch.
    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();

    if (meta.op == kPut) {
        rocksdb_writebatch_put_cf(wb, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key), ZSTR_VAL(val_s.s), ZSTR_LEN(val_s.s));
    } else {
        rocksdb_writebatch_merge_cf(wb, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key), ZSTR_VAL(val_s.s), ZSTR_LEN(val_s.s));
    }

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store 4");

    // Write the batch to storage.
    char *err = NULL;
    rocksdb_writeoptions_t* woptions;
    woptions = rocksdb_writeoptions_create();
    //rocksdb_writeoptions_disable_WAL(woptions, 1);
    rocksdb_write(UC_G(db_h), woptions, wb, &err);

    // Clean up.
    rocksdb_writeoptions_destroy(woptions);
    rocksdb_writebatch_destroy(wb);
    smart_str_free(&val_s);

    //php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cache_store 5");

    if (err != NULL) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to store to user cache: %s", err);
        return 0;
    }

    return 1;
}
/* }}} */

/* {{{ uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const zend_bool exclusive)
 */
static void uc_store_helper(INTERNAL_FUNCTION_PARAMETERS, const uc_operation_t op)
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
		            if(!uc_cache_store(hkey, hentry, (uint32_t) ttl, op, 0, 0)) {
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
    			if(uc_cache_store(Z_STR_P(key), val, (uint32_t) ttl, op, 0, 0)) {
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
    if (uc_cache_store(key, NULL, 0, kInc, step, 0)) {
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
    zend_string *key;
    zend_long vals[2];
    zval *new_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sll", &key, &vals[0], &vals[1]) == FAILURE) {
        return;
    }

    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uc_cas 1");


    if (uc_cache_store(key, NULL, 0, kCAS, vals[0], vals[1])) {
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
    val_s = rocksdb_get_cf(UC_G(db_h), roptions, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key), &val_s_len, &err);
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
    rocksdb_writebatch_delete_cf(wb, UC_G(cf_h), ZSTR_VAL(key), ZSTR_LEN(key));
    woptions = rocksdb_writeoptions_create();
    //rocksdb_writeoptions_disable_WAL(woptions, 1);
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

