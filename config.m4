PHP_ARG_ENABLE(uc, whether to enable User Cache support,
[  --enable-uc           Enable User Cache support])

if test "$PHP_UC" != "no"; then
  AC_DEFINE(UC, 1, [ ])

  dnl Search for and link to LevelDB
  if test -r $PHP_UC/include/leveldb/c.h; then
    LEVELDB_DIR=$PHP_UC
  else
    AC_MSG_CHECKING(for LevelDB in default path)
    for i in /usr/local /usr; do
      if test -r $i/include/leveldb/c.h; then
        LEVELDB_DIR=$i
        AC_MSG_RESULT(found in $i)
        break
      fi
    done
  fi

  AC_MSG_CHECKING([for LevelDB])
  PHP_CHECK_LIBRARY(leveldb, leveldb_open, [
    PHP_ADD_LIBRARY_WITH_PATH(leveldb, $LEVELDB_DIR, UC_SHARED_LIBADD)
    PHP_ADD_INCLUDE($LEVELDB_DIR/include)
  ],[
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please install LevelDB first or check that leveldb-devel is present])
  ],[
    APM_SHARED_LIBADD -lleveldb
  ])

  AC_DEFINE(HAVE_LEVELDB, 1, [LevelDB found and included])


  dnl if test -z "$LEVELDB_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please install LevelDB development resources])
  dnl fi

  dnl PHP_ADD_LIBRARY_WITH_PATH(leveldb, $LEVELDB_DIR, LEVELDB_SHARED_LIBADD)
  dnl PHP_ADD_INCLUDE($LEVELDB_DIR/include)
  PHP_SUBST(UC_SHARED_LIBADD)

  PHP_NEW_EXTENSION(uc, uc.c, $ext_shared)
  AC_DEFINE(HAVE_UC, 1, [ ])
fi

