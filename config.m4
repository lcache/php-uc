PHP_ARG_ENABLE(uc, whether to enable User Cache support,
[  --enable-uc           Enable User Cache support])

if test "$PHP_UC" != "no"; then
  AC_DEFINE(UC, 1, [ ])

  dnl Enable support for C++
  CXX_FLAGS="-std=c++14 -Wall -DDEBUG -g"
  CXXFLAGS="-std=c++14 -Wall -DDEBUG -g"
  AC_LANG_CPLUSPLUS
  PHP_REQUIRE_CXX()

  PHP_ADD_LIBRARY(stdc++, 1, UC_SHARED_LIBADD)
  PHP_ADD_LIBRARY(boost_interprocess, 1, UC_SHARED_LIBADD)

  uc_sources="uc.c \
              storage.cpp"

  PHP_NEW_EXTENSION(uc, $uc_sources, $ext_shared)
  AC_DEFINE(HAVE_UC, 1, [ ])
fi

