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
  +----------------------------------------------------------------------+
 */

#ifndef PHP_UC_H
#define PHP_UC_H 1

#ifdef ZTS
#include "TSRM.h"
#endif

#include "marshalling.h"
#include "persistence.h"
#include "workers.h"

ZEND_BEGIN_MODULE_GLOBALS(uc)
    zend_bool enabled;
    long concurrency;
    char* storage_directory;
    uc_persistence_t persistence;
    uc_worker_pool_t* pool;
ZEND_END_MODULE_GLOBALS(uc)

#ifdef ZTS
#define UC_G(v) TSRMG(uc_globals_id, zend_uc_globals *, v)
#else
#define UC_G(v) (uc_globals.v)
#endif

#define PHP_UC_VERSION "1.0"
#define PHP_UC_EXTNAME "uc"

PHP_MINIT_FUNCTION(uc);
PHP_MSHUTDOWN_FUNCTION(uc);
PHP_RINIT_FUNCTION(uc);

PHP_FUNCTION(uc_test);
PHP_FUNCTION(uc_compact);
PHP_FUNCTION(uc_clear_cache);
PHP_FUNCTION(uc_store);
PHP_FUNCTION(uc_fetch);
PHP_FUNCTION(uc_delete);
PHP_FUNCTION(uc_inc);
PHP_FUNCTION(uc_add);
PHP_FUNCTION(uc_cas);

extern zend_module_entry uc_module_entry;
#define phpext_uc_prt &uc_module_entry

#endif
