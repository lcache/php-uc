<?php

// Run using the commands:
// phpize
// ./configure --enable-uc --with-rocksdb
// make
// php -d extension=modules/uc.so test.php

echo uc_test() . PHP_EOL;

echo 'Old Value' . PHP_EOL;
$retval = uc_fetch('mykey', $success);
print_r($retval);
echo 'uc_fetch: ' . $success . PHP_EOL;

echo 'Old Value (Deleted?)' . PHP_EOL;
$success = uc_clear_cache();
echo 'uc_clear_cache: ' . $success . PHP_EOL;
$retval = uc_fetch('mykey', $success);
print_r($retval);
echo 'uc_fetch: ' . $success . PHP_EOL;

echo 'Simple Value' . PHP_EOL;
$success = uc_store('mykey', 'myvalue');
echo 'uc_store: ' . $success . PHP_EOL;
$retval = uc_fetch('mykey', $success);
echo 'Got: ' . $retval . PHP_EOL;
echo 'uc_fetch: ' . $success . PHP_EOL;

echo 'Complex Value' . PHP_EOL;
$success = uc_store('mykey', ['i', 'am', 'complex']);
echo 'uc_store: ' . $success . PHP_EOL;
$retval = uc_fetch('mykey', $success);
print_r($retval);
echo 'uc_fetch: ' . $success . PHP_EOL;

echo 'Deleted' . PHP_EOL;
$success = uc_delete('mykey');
echo 'uc_delete: ' . $success . PHP_EOL;
$retval = uc_fetch('mykey', $success);
print_r($retval);
echo 'uc_fetch: ' . ($success ? true : false) . PHP_EOL;

echo 'TTL' . PHP_EOL;
$success = uc_store('mykey', 'myvalue', 1984);
echo 'uc_store: ' . $success . PHP_EOL;
uc_compact();
$retval = uc_fetch('mykey', $success);
echo 'Got: ' . $retval . PHP_EOL;
echo 'uc_fetch (should fail): ' . $success . PHP_EOL;

echo 'Storing again' . PHP_EOL;
$success = uc_store('mykey', ['i', 'am', 'complex']);
echo 'uc_store: ' . $success . PHP_EOL;

