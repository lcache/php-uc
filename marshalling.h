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

#ifndef UC_MARSHALLING_H
#define UC_MARSHALLING_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    kPut = 0,
    kInc = 1,
    kAdd = 2,
    kCAS = 3,
    kGet = 4,
    kDelete = 5
} uc_operation_t;

typedef enum {
    kNone = 0,
    kSerialized = 1,
    kLong = 2
} uc_value_type_t;

typedef struct {
    uc_value_type_t value_type;
    long value;
    long cas_value_or_inc;
    size_t ttl;
    time_t created;
    time_t modified;
    uc_operation_t op;
    size_t version;
    uint32_t magic;
} uc_metadata_t;

int uc_read_metadata(const char* val, size_t val_size, uc_metadata_t* meta);
int uc_metadata_is_fresh(uc_metadata_t meta, time_t now);
int uc_strip_metadata(const char* val, size_t* val_size, uc_metadata_t* meta);
int uc_init_metadata(uc_metadata_t* meta);
void uc_print_metadata(const char *val, size_t val_size);

#endif
