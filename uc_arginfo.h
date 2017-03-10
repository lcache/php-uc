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
  |          Joe Watkins <krakjoe@php.net>                               |
  +----------------------------------------------------------------------+
 */

#ifndef UC_ARGINFO_H
#define UC_ARGINFO_H

/* {{{ arginfo */

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_store, 0, 0, 2)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, var)
ZEND_ARG_INFO(0, ttl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_enabled, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_cache_info, 0, 0, 0)
ZEND_ARG_INFO(0, limited)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_clear_cache, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_size, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_dump, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_key_info, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_sma_info, 0, 0, 0)
ZEND_ARG_INFO(0, limited)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_uc_delete, 0)
ZEND_ARG_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_fetch, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(1, success)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_inc, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, step)
ZEND_ARG_INFO(1, success)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_uc_cas, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, old)
ZEND_ARG_INFO(0, new)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_uc_exists, 0)
ZEND_ARG_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uc_entry, 0, 0, 2)
ZEND_ARG_INFO(0, key)
ZEND_ARG_TYPE_INFO(0, generator, IS_CALLABLE, 0)
ZEND_ARG_TYPE_INFO(0, ttl, IS_LONG, 0)
ZEND_END_ARG_INFO()
/* }}} */

#endif
