* Move DB initialization later so it runs after PHP-FPM drops privileges.
* Fix `uc_clear_cache()`, possibly with optimization:
  https://github.com/facebook/rocksdb/wiki/Delete-A-Range-Of-Keys
* Finish `UCIterator`.
* Add existing APCu tests.
* Add option to clear DB at PHP startup.
* Use `rocksdb_writeoptions_disable_WAL` and write a telltale value on clean
  shutdown. Clear the full DB on startup if the value is missing.
* Get static linking to RocksDB working.
* Use kPointInTimeConsistency for WAL recovery.
* Finish `.travis.yml`:

        - php -n run-tests.php -n -d extension_dir=./modules/ -d extension=uc.so -d uc.enable=1 -p `phpenv which php` --show-diff --set-timeout 120
