/*
  +----------------------------------------------------------------------+
  | UC                                                                   |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2011 The PHP Group                                |
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
  |          Brian Shire <shire@php.net>                                 |
  +----------------------------------------------------------------------+
 */

#include "php_uc.h"
#include "uc_iterator.h"
#include "uc_cache.h"

#include "ext/standard/md5.h"
#include "SAPI.h"
#include "zend_interfaces.h"

static zend_class_entry *uc_iterator_ce;
zend_object_handlers uc_iterator_object_handlers;

zend_class_entry* uc_iterator_get_ce(void) {
	return uc_iterator_ce;
}

/* {{{ uc_iterator_item */
static uc_iterator_item_t* uc_iterator_item_ctor(uc_iterator_t *iterator, uc_cache_slot_t **slot_pp) {
    zval zvalue;
    uc_cache_slot_t *slot = *slot_pp;
    uc_context_t ctxt = {0, };
    uc_iterator_item_t *item = ecalloc(1, sizeof(uc_iterator_item_t));

    array_init(&item->value);

	item->key = slot->key.str;

    if (UC_ITER_TYPE & iterator->format) {
		add_assoc_string_ex(&item->value, "type", sizeof("type")-1, "user");
	}

	if (UC_ITER_KEY & iterator->format) {
		add_assoc_str(&item->value, "key", zend_string_copy(item->key));
	}

    if (UC_ITER_VALUE & iterator->format) {
    	uc_cache_make_context(&ctxt, UC_CONTEXT_NOSHARE, UC_UNPOOL, UC_COPY_OUT, 0);
    	ZVAL_UNDEF(&zvalue);
        uc_cache_fetch_zval(&ctxt, &zvalue, &slot->value->val);
        add_assoc_zval(&item->value, "value", &zvalue);
        uc_pool_destroy(ctxt.pool);
    }

    if (UC_ITER_NUM_HITS & iterator->format) {
        add_assoc_long(&item->value, "num_hits", slot->nhits);
    }
    if (UC_ITER_MTIME & iterator->format) {
        add_assoc_long(&item->value, "mtime", slot->key.mtime);
    }
    if (UC_ITER_CTIME & iterator->format) {
        add_assoc_long(&item->value, "creation_time", slot->ctime);
    }
    if (UC_ITER_DTIME & iterator->format) {
        add_assoc_long(&item->value, "deletion_time", slot->dtime);
    }
    if (UC_ITER_ATIME & iterator->format) {
        add_assoc_long(&item->value, "access_time", slot->atime);
    }
    if (UC_ITER_REFCOUNT & iterator->format) {
        add_assoc_long(&item->value, "ref_count", slot->value->ref_count);
    }
    if (UC_ITER_MEM_SIZE & iterator->format) {
        add_assoc_long(&item->value, "mem_size", slot->value->mem_size);
    }
    if (UC_ITER_TTL & iterator->format) {
        add_assoc_long(&item->value, "ttl", slot->value->ttl);
    }

    return item;
}
/* }}} */

/* {{{ uc_iterator_clone */
static zend_object* uc_iterator_clone(zval *zobject) {
    uc_error(UC_ITERATOR_NAME " object cannot be cloned");
    return NULL;
}
/* }}} */

/* {{{ uc_iterator_item_dtor */
static void uc_iterator_item_dtor(uc_iterator_item_t *item) {
    zval_ptr_dtor(&item->value);
    efree(item);
}
/* }}} */

/* {{{ uc_iterator_free */
static void uc_iterator_free(zend_object *object) {
    uc_iterator_t *iterator = uc_iterator_fetch_from(object);

    if (iterator->initialized == 0) {
		zend_object_std_dtor(object);
        return;
    }

    while (uc_stack_size(iterator->stack) > 0) {
        uc_iterator_item_dtor(uc_stack_pop(iterator->stack));
    }

    uc_stack_destroy(iterator->stack);

#ifdef ITERATOR_PCRE
    if (iterator->regex) {
        zend_string_release(iterator->regex);
    }
#endif

    if (iterator->search_hash) {
        zend_hash_destroy(iterator->search_hash);
        efree(iterator->search_hash);
    }
    iterator->initialized = 0;

	zend_object_std_dtor(object);
}
/* }}} */

/* {{{ uc_iterator_create */
zend_object* uc_iterator_create(zend_class_entry *ce) {
    uc_iterator_t *iterator =
		(uc_iterator_t*) emalloc(sizeof(uc_iterator_t) + zend_object_properties_size(ce));

    zend_object_std_init(&iterator->obj, ce);
    object_properties_init(&iterator->obj, ce);

    iterator->initialized = 0;
    iterator->stack = NULL;
	iterator->regex = NULL;
    iterator->search_hash = NULL;
	iterator->obj.handlers = &uc_iterator_object_handlers;

    return &iterator->obj;
}
/* }}} */

/* {{{ uc_iterator_search_match
 *       Verify if the key matches our search parameters
 */
static int uc_iterator_search_match(uc_iterator_t *iterator, uc_cache_slot_t **slot) {
    int rval = 1;

#ifdef ITERATOR_PCRE
    if (iterator->regex) {
        rval = (pcre_exec(iterator->re, NULL, ZSTR_VAL((*slot)->key.str), ZSTR_LEN((*slot)->key.str), 0, 0, NULL, 0) >= 0);
    }
#endif

    if (iterator->search_hash) {
        rval = zend_hash_exists(iterator->search_hash, (*slot)->key.str);
    }

    return rval;
}
/* }}} */

/* {{{ uc_iterator_check_expiry */
static int uc_iterator_check_expiry(uc_cache_t* cache, uc_cache_slot_t **slot, time_t t)
{
    if((*slot)->value->ttl) {
        if((time_t) ((*slot)->ctime + (*slot)->value->ttl) < t) {
            return 0;
        }
    } else if(cache->ttl) {
        if((*slot)->ctime + cache->ttl < t) {
            return 0;
        }
    }

    return 1;
}
/* }}} */

/* {{{ uc_iterator_fetch_active */
static int uc_iterator_fetch_active(uc_iterator_t *iterator) {
    int count=0;
    uc_cache_slot_t **slot;
    uc_iterator_item_t *item;
    time_t t;

    t = uc_time();

    while (uc_stack_size(iterator->stack) > 0) {
        uc_iterator_item_dtor(uc_stack_pop(iterator->stack));
    }

	php_uc_try(UC_RLOCK(uc_user_cache->header), {
		while(count <= iterator->chunk_size && iterator->slot_idx < uc_user_cache->nslots) {
		    slot = &uc_user_cache->slots[iterator->slot_idx];
		    while(*slot) {
		        if (uc_iterator_check_expiry(uc_user_cache, slot, t)) {
		            if (uc_iterator_search_match(iterator, slot)) {
		                count++;
		                item = uc_iterator_item_ctor(iterator, slot);
		                if (item) {
		                    uc_stack_push(iterator->stack, item);
		                }
		            }
		        }
		        slot = &(*slot)->next;
		    }
		    iterator->slot_idx++;
		}
	}, {
		iterator->stack_idx = 0;
		UC_RUNLOCK(uc_user_cache->header)
	});

    return count;
}
/* }}} */

/* {{{ uc_iterator_fetch_deleted */
static int uc_iterator_fetch_deleted(uc_iterator_t *iterator) {
    int count=0;
    uc_cache_slot_t **slot;
    uc_iterator_item_t *item;

    php_uc_try(UC_RLOCK(uc_user_cache->header), {
		slot = &uc_user_cache->header->gc;
		while ((*slot) && count <= iterator->slot_idx) {
		    count++;
		    slot = &(*slot)->next;
		}
		count = 0;
		while ((*slot) && count < iterator->chunk_size) {
		    if (uc_iterator_search_match(iterator, slot)) {
		        count++;
		        item = uc_iterator_item_ctor(iterator, slot);
		        if (item) {
		            uc_stack_push(iterator->stack, item);
		        }
		    }
		    slot = &(*slot)->next;
		}
	}, {
		iterator->slot_idx += count;
    	iterator->stack_idx = 0;
		UC_RUNLOCK(uc_user_cache->header);
	});

    return count;
}
/* }}} */

/* {{{ uc_iterator_totals */
static void uc_iterator_totals(uc_iterator_t *iterator) {
    uc_cache_slot_t **slot;
    int i;

    php_uc_try(UC_RLOCK(uc_user_cache->header), {
		for (i=0; i < uc_user_cache->nslots; i++) {
		    slot = &uc_user_cache->slots[i];
		    while((*slot)) {
		        if (uc_iterator_search_match(iterator, slot)) {
		            iterator->size += (*slot)->value->mem_size;
		            iterator->hits += (*slot)->nhits;
		            iterator->count++;
		        }
		        slot = &(*slot)->next;
		    }
		}
	}, {
		iterator->totals_flag = 1;
		UC_RUNLOCK(uc_user_cache->header);
	});
}
/* }}} */

void uc_iterator_obj_init(uc_iterator_t *iterator, zval *search, zend_long format, zend_long chunk_size, zend_long list)
{
    if (!UCG(enabled)) {
        uc_error("UC must be enabled to use " UC_ITERATOR_NAME);
    }

    if (chunk_size < 0) {
        uc_error(UC_ITERATOR_NAME " chunk size must be 0 or greater");
        return;
    }

    if (format > UC_ITER_ALL) {
        uc_error(UC_ITERATOR_NAME " format is invalid");
        return;
    }

    if (list == UC_LIST_ACTIVE) {
        iterator->fetch = uc_iterator_fetch_active;
    } else if (list == UC_LIST_DELETED) {
        iterator->fetch = uc_iterator_fetch_deleted;
    } else {
        uc_warning(UC_ITERATOR_NAME " invalid list type");
        return;
    }

    iterator->slot_idx = 0;
    iterator->stack_idx = 0;
    iterator->key_idx = 0;
    iterator->chunk_size = chunk_size == 0 ? UC_DEFAULT_CHUNK_SIZE : chunk_size;
    iterator->stack = uc_stack_create(chunk_size);
    iterator->format = format;
    iterator->totals_flag = 0;
    iterator->count = 0;
    iterator->size = 0;
    iterator->hits = 0;
    iterator->regex = NULL;
    iterator->search_hash = NULL;
    if (search && Z_TYPE_P(search) == IS_STRING && Z_STRLEN_P(search)) {
#ifdef ITERATOR_PCRE
        iterator->regex = zend_string_copy(Z_STR_P(search));
        iterator->re = pcre_get_compiled_regex(iterator->regex, NULL, NULL);

        if(!iterator->re) {
            uc_error("Could not compile regular expression: %s", Z_STRVAL_P(search));
			zend_string_release(iterator->regex);
        }
#else
        uc_error("Regular expressions support is not enabled, please enable PCRE for " UC_ITERATOR_NAME " regex support.");
#endif
    } else if (search && Z_TYPE_P(search) == IS_ARRAY) {
        Z_ADDREF_P(search);
        iterator->search_hash = uc_flip_hash(Z_ARRVAL_P(search));
    }
    iterator->initialized = 1;
}

/* {{{ proto object UCuIterator::__construct([ mixed search [, long format [, long chunk_size [, long list ]]]]) */
PHP_METHOD(uc_iterator, __construct) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());
    zend_long format = UC_ITER_ALL;
    zend_long chunk_size=0;
    zval *search = NULL;
    zend_long list = UC_LIST_ACTIVE;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|zlll", &search, &format, &chunk_size, &list) == FAILURE) {
        return;
    }

	uc_iterator_obj_init(iterator, search, format, chunk_size, list);
}
/* }}} */

/* {{{ proto UCuIterator::rewind() */
PHP_METHOD(uc_iterator, rewind) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0) {
        RETURN_FALSE;
    }

    iterator->slot_idx = 0;
    iterator->stack_idx = 0;
    iterator->key_idx = 0;
    iterator->fetch(iterator);
}
/* }}} */

/* {{{ proto boolean UCuIterator::valid() */
PHP_METHOD(uc_iterator, valid) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0) {
        RETURN_FALSE;
    }

    if (uc_stack_size(iterator->stack) == iterator->stack_idx) {
        iterator->fetch(iterator);
    }

    RETURN_BOOL(uc_stack_size(iterator->stack) == 0 ? 0 : 1);
}
/* }}} */

/* {{{ proto mixed UCuIterator::current() */
PHP_METHOD(uc_iterator, current) {
    uc_iterator_item_t *item;
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0) {
        RETURN_FALSE;
    }

    if (uc_stack_size(iterator->stack) == iterator->stack_idx) {
        if (iterator->fetch(iterator) == 0) {
            RETURN_FALSE;
        }
    }

    item = uc_stack_get
		(iterator->stack, iterator->stack_idx);
    ZVAL_COPY(return_value, &item->value);
}
/* }}} */

/* {{{ proto string UCuIterator::key() */
PHP_METHOD(uc_iterator, key) {
    uc_iterator_item_t *item;
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0 || uc_stack_size(iterator->stack) == 0) {
        RETURN_FALSE;
    }

    if (uc_stack_size(iterator->stack) == iterator->stack_idx) {
        if (iterator->fetch(iterator) == 0) {
            RETURN_FALSE;
        }
    }

    item = uc_stack_get(iterator->stack, iterator->stack_idx);

    if (item->key) {
        RETURN_STR_COPY(item->key);
    } else {
        RETURN_LONG(iterator->key_idx);
    }
}
/* }}} */

/* {{{ proto UCuIterator::next() */
PHP_METHOD(uc_iterator, next) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0 || uc_stack_size(iterator->stack) == 0) {
        RETURN_FALSE;
    }

    iterator->stack_idx++;
    iterator->key_idx++;

    RETURN_TRUE;
}
/* }}} */

/* {{{ proto long UCuIterator::getTotalHits() */
PHP_METHOD(uc_iterator, getTotalHits) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0) {
        RETURN_FALSE;
    }

    if (iterator->totals_flag == 0) {
        uc_iterator_totals(iterator);
    }

    RETURN_LONG(iterator->hits);
}
/* }}} */

/* {{{ proto long UCuIterator::getTotalSize() */
PHP_METHOD(uc_iterator, getTotalSize) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0) {
        RETURN_FALSE;
    }

    if (iterator->totals_flag == 0) {
        uc_iterator_totals(iterator);
    }

    RETURN_LONG(iterator->size);
}
/* }}} */

/* {{{ proto long UCuIterator::getTotalCount() */
PHP_METHOD(uc_iterator, getTotalCount) {
    uc_iterator_t *iterator = uc_iterator_fetch(getThis());

    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }

    if (iterator->initialized == 0) {
        RETURN_FALSE;
    }

    if (iterator->totals_flag == 0) {
        uc_iterator_totals(iterator);
    }

    RETURN_LONG(iterator->count);
}
/* }}} */

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_iterator___construct, 0, 0, 0)
	ZEND_ARG_INFO(0, search)
	ZEND_ARG_INFO(0, format)
	ZEND_ARG_INFO(0, chunk_size)
	ZEND_ARG_INFO(0, list)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_iterator_void, 0, 0, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ uc_iterator_functions */
static zend_function_entry uc_iterator_functions[] = {
    PHP_ME(uc_iterator, __construct, arginfo_uc_iterator___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(uc_iterator, rewind, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, current, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, key, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, next, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, valid, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, getTotalHits, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, getTotalSize, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_ME(uc_iterator, getTotalCount, arginfo_uc_iterator_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
/* }}} */

/* {{{ uc_iterator_init */
int uc_iterator_init(int module_number) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, UC_ITERATOR_NAME, uc_iterator_functions);
    uc_iterator_ce = zend_register_internal_class(&ce);
    uc_iterator_ce->create_object = uc_iterator_create;
    zend_class_implements(uc_iterator_ce, 1, zend_ce_iterator);

    REGISTER_LONG_CONSTANT("UC_LIST_ACTIVE", UC_LIST_ACTIVE, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_LIST_DELETED", UC_LIST_DELETED, CONST_PERSISTENT | CONST_CS);
	REGISTER_LONG_CONSTANT("UC_ITER_TYPE", UC_ITER_TYPE, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_KEY", UC_ITER_KEY, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_VALUE", UC_ITER_VALUE, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_NUM_HITS", UC_ITER_NUM_HITS, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_MTIME", UC_ITER_MTIME, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_CTIME", UC_ITER_CTIME, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_DTIME", UC_ITER_DTIME, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_ATIME", UC_ITER_ATIME, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_REFCOUNT", UC_ITER_REFCOUNT, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_MEM_SIZE", UC_ITER_MEM_SIZE, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_TTL", UC_ITER_TTL, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_NONE", UC_ITER_NONE, CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("UC_ITER_ALL", UC_ITER_ALL, CONST_PERSISTENT | CONST_CS);

    memcpy(&uc_iterator_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));

    uc_iterator_object_handlers.clone_obj = uc_iterator_clone;
	uc_iterator_object_handlers.free_obj = uc_iterator_free;
	uc_iterator_object_handlers.offset = XtOffsetOf(uc_iterator_t, obj);

    return SUCCESS;
}
/* }}} */

/* {{{ uc_iterator_delete */
int uc_iterator_delete(zval *zobj) {
    uc_iterator_t *iterator;
    zend_class_entry *ce = Z_OBJCE_P(zobj);
    uc_iterator_item_t *item;

    if (!ce || !instanceof_function(ce, uc_iterator_ce)) {
        uc_error("uc_delete object argument must be instance of " UC_ITERATOR_NAME ".");
        return 0;
    }
    iterator = uc_iterator_fetch(zobj);

    if (iterator->initialized == 0) {
        return 0;
    }

    while (iterator->fetch(iterator)) {
        while (iterator->stack_idx < uc_stack_size(iterator->stack)) {
            item = uc_stack_get(iterator->stack, iterator->stack_idx++);
            uc_cache_delete(item->key);
        }
    }

    return 1;
}
/* }}} */

