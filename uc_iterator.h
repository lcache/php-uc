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

#ifndef UC_ITERATOR_H
#define UC_ITERATOR_H

#if HAVE_PCRE || HAVE_BUNDLED_PCRE
#   include "ext/pcre/php_pcre.h"
#   include "zend_smart_str.h"
#   define ITERATOR_PCRE 1
#endif


#define UC_ITERATOR_NAME "UCIterator"

#define UC_DEFAULT_CHUNK_SIZE 100

#define UC_LIST_ACTIVE   0x1
#define UC_LIST_DELETED  0x2

#define UC_ITER_TYPE		(1 << 0)
#define UC_ITER_KEY        (1 << 1)
#define UC_ITER_VALUE      (1 << 2)
#define UC_ITER_NUM_HITS   (1 << 3)
#define UC_ITER_MTIME      (1 << 4)
#define UC_ITER_CTIME      (1 << 5)
#define UC_ITER_DTIME      (1 << 6)
#define UC_ITER_ATIME      (1 << 7)
#define UC_ITER_REFCOUNT   (1 << 8)
#define UC_ITER_MEM_SIZE   (1 << 9)
#define UC_ITER_TTL        (1 << 10)

#define UC_ITER_NONE       0
#define UC_ITER_ALL        (0xffffffffL)

typedef void* (*uc_iterator_item_cb_t)(uc_cache_slot_t **slot);

/* {{{ uc_iterator_t */
typedef struct _uc_iterator_t {
    short int initialized;   /* sanity check in case __construct failed */
    zend_long format;             /* format bitmask of the return values ie: key, value, info */
    int (*fetch)(struct _uc_iterator_t *iterator);
                             /* fetch callback to fetch items from cache slots or lists */
    zend_long slot_idx;           /* index to the slot array or linked list */
    zend_long chunk_size;         /* number of entries to pull down per fetch */
    uc_stack_t *stack;      /* stack of entries pulled from cache */
    int stack_idx;           /* index into the current stack */
#ifdef ITERATOR_PCRE
    pcre *re;                /* regex filter on entry identifiers */
#endif
    zend_string *regex;
    HashTable *search_hash;  /* hash of keys to iterate over */
    zend_long key_idx;            /* incrementing index for numerical keys */
    short int totals_flag;   /* flag if totals have been calculated */
    zend_long hits;               /* hit total */
    size_t size;             /* size total */
    zend_long count;              /* count total */
    zend_object obj;
} uc_iterator_t;
/* }}} */

#define uc_iterator_fetch_from(o) ((uc_iterator_t*)((char*)o - XtOffsetOf(uc_iterator_t, obj)))
#define uc_iterator_fetch(z) uc_iterator_fetch_from(Z_OBJ_P(z))

/* {{{ uc_iterator_item */
typedef struct _uc_iterator_item_t {
    zend_string *key;
    zval value;
} uc_iterator_item_t;
/* }}} */

void uc_iterator_obj_init(
	uc_iterator_t *iterator,
	zval *search,
	zend_long format,
	zend_long chunk_size,
	zend_long list);
zend_class_entry* uc_iterator_get_ce(void);
int uc_iterator_init(int module_number);

extern int uc_iterator_delete(zval *key);
#endif

