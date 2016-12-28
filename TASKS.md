* Fix `uc_clear_cache()`, possibly with optimization:
  https://github.com/facebook/rocksdb/wiki/Delete-A-Range-Of-Keys
* Finish `UCIterator`.
* Build compaction filter for TTLs.
* Filter expired items via `rocksdb_filterpolicy_create`.
* Add countrer support via `rocksdb_mergeoperator_create`.
* Add unsafe implementations for `uc_cas()` and `uc_add()`.
* Add locks to truly support `uc_cas()` and `uc_add()`. Use TransactionDB?
* Add existing APCu tests.
* Add option to clear DB at PHP startup.
* Use `rocksdb_writeoptions_disable_WAL` and write a telltale value on clean
  shutdown. Clear the full DB on startup if the value is missing.
* Get static linking to RocksDB working.
* Use kPointInTimeConsistency for WAL recovery.
* Finish `.travis.yml`:

        - php -n run-tests.php -n -d extension_dir=./modules/ -d extension=uc.so -d uc.enable=1 -p `phpenv which php` --show-diff --set-timeout 120
