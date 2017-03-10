PHP_ARG_ENABLE(uc, whether to enable User Cache support,
[  --enable-uc           Enable User Cache support])

PHP_ARG_WITH(rocksdb, path to RocksDB for User Cache,
[  --with-rocksdb=DIR    Directory with static build of RocksDB])

if test "$PHP_UC" != "no"; then
  AC_DEFINE(UC, 1, [ ])

  dnl Enable support for C++
  CXX_FLAGS="-std=c++14"
  CXXFLAGS="-std=c++14"
  AC_LANG_CPLUSPLUS
  PHP_REQUIRE_CXX()

  PHP_ADD_LIBRARY(stdc++, 1, UC_SHARED_LIBADD)
  PHP_ADD_LIBRARY(boost_interprocess, 1, UC_SHARED_LIBADD)

  uc_sources="uc.c \
              storage.cpp"

  PHP_NEW_EXTENSION(uc, $uc_sources, $ext_shared)
  AC_DEFINE(HAVE_UC, 1, [ ])
fi

