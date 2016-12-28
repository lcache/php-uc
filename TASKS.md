* Fix `uc_clear_cache()`
* Finish `UCIterator`
* Build compaction filter for TTLs
* Filter for current TTLs at read time
* Build merge support for counters
* Add locks to support `uc_cas()` and `uc_add()`
* Add existing APCu tests
* Add option to clear DB at PHP startup.
* Finish `.travis.yml`:

        - php -n run-tests.php -n -d extension_dir=./modules/ -d extension=uc.so -d uc.enable=1 -p `phpenv which php` --show-diff --set-timeout 120
