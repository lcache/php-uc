* Fix `uc_clear_cache()`.
* Finish `UCIterator`.
* Build compaction filter for TTLs.
* Filter for current TTLs at read time.
* Build merge support for counters.
* Add unsafe implementations for `uc_cas()` and `uc_add()`.
* Add locks to truly support `uc_cas()` and `uc_add()`. Use TransactionDB?
* Add existing APCu tests.
* Add option to clear DB at PHP startup.
* Use write_option.disableWAL and write a telltale value on clean shutdown.
  Clear the full DB on startup if the value is missing.
* Get static linking to RocksDB working.
* Finish `.travis.yml`:

        - php -n run-tests.php -n -d extension_dir=./modules/ -d extension=uc.so -d uc.enable=1 -p `phpenv which php` --show-diff --set-timeout 120
