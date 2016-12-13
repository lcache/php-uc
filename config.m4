PHP_ARG_ENABLE(uc, whether to enable User Cache support,
[  --enable-uc           Enable User Cache support])

PHP_ARG_WITH(rocksdb, path to RocksDB for User Cache,
[  --with-rocksdb=DIR    Directory for RocksDB])

if test "$PHP_UC" != "no"; then
  AC_DEFINE(UC, 1, [ ])

  dnl Search for and link to RocksDB
  if test "$PHP_ROCKSDB" != "no"; then
    ROCKSDB_DIR=$PHP_ROCKSDB
	  AC_MSG_RESULT(using $ROCKSDB_DIR)
  else
    if test -r $PHP_UC/include/rocksdb/c.h; then
      ROCKSDB_DIR=$PHP_UC
    else
      AC_MSG_CHECKING(for RocksDB in default path)
      for i in /usr/local /usr; do
        if test -r $i/include/rocksdb/c.h; then
	  ROCKSDB_DIR=$i
	  AC_MSG_RESULT(found in $i)
	  break
        fi
      done
    fi
  fi

  AC_MSG_CHECKING([for RocksDB])
  PHP_CHECK_LIBRARY(rocksdb, rocksdb_open, [
    PHP_ADD_LIBRARY_WITH_PATH(rocksdb, $ROCKSDB_DIR, UC_SHARED_LIBADD)
    PHP_ADD_INCLUDE($ROCKSDB_DIR/include)
  ],[
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please install RocksDB first or check that rocksdb-devel is present])
  ],[
    UC_SHARED_LIBADD --library-path=$ROCKSDB_DIR -lrocksdb
  ])

  AC_DEFINE(HAVE_ROCKSDB, 1, [RocksDB found and included])


  dnl if test -z "$ROCKSDB_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please install RocksDB development resources])
  dnl fi

  PHP_SUBST(UC_SHARED_LIBADD)

  PHP_NEW_EXTENSION(uc, uc.c, $ext_shared)
  AC_DEFINE(HAVE_UC, 1, [ ])
fi

