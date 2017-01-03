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

#ifndef UC_PERSISTENCE_H
#define UC_PERSISTENCE_H

#include <rocksdb/c.h>

typedef struct {
    rocksdb_t* db_h;
    rocksdb_options_t* db_options;
    rocksdb_options_t* cf_options;
    rocksdb_compactionfilter_t* cfilter;
    rocksdb_column_family_handle_t* cf_h;
} uc_persistence_t;

int uc_persistence_init(const char* storage_directory, uc_persistence_t* p);
int uc_persistence_destroy(uc_persistence_t* p);

#endif
