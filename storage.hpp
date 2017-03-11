/*
  +----------------------------------------------------------------------+
  | UC                                                                   |
  +----------------------------------------------------------------------+
  | Copyright (c) 2017 David Strauss                                     |
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

#ifndef UC_DATABASE_H
#define UC_DATABASE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void* uc_storage_t;

uc_storage_t uc_storage_init(size_t size, char** errptr);
int uc_storage_store(uc_storage_t st_opaque,
                     const char* address,
                     size_t address_len,
                     const char* data,
                     size_t data_size,
                     time_t expiration,
                     int exclusive,
                     char** errptr);

int uc_storage_store_long(uc_storage_t st_opaque,
                          const char* address,
                          size_t address_len,
                          const long data,
                          time_t expiration,
                          int exclusive,
                          char** errptr);

int uc_storage_increment(
  uc_storage_t st_opaque, const char* address, size_t address_len, long step, zval** dst, char** errptr);

int uc_storage_cas(
  uc_storage_t st_opaque, const char* address, size_t address_len, long next, long expected, char** errptr);

void uc_storage_clear(uc_storage_t st_opaque, char** errptr);
int uc_storage_get(uc_storage_t st_opaque, const char* address, size_t address_len, zval** dst, char** errptr);
void uc_string_free(char* strptr);
size_t uc_storage_size(uc_storage_t st_opaque, char** errptr);
int uc_storage_exists(uc_storage_t st_opaque, const char* address, size_t address_len, char** errptr);
void uc_storage_dump(uc_storage_t st_opaque, char** errptr);
int uc_storage_delete(uc_storage_t st_opaque, const char* address, size_t address_len, char** errptr);

#ifdef __cplusplus
}
#endif

#endif
