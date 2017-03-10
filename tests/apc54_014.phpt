--TEST--
UC: Bug #61742 preload_path does not work due to incorrect string length (variant 1) (php 5.4)
--SKIPIF--
<?php
    require_once(dirname(__FILE__) . '/skipif.inc'); 
    if (PHP_MAJOR_VERSION < 5 || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 4)) {
		die('skip PHP 5.4+ only');
	}
	if(PHP_ZTS === 1) {
		die('skip PHP non-ZTS only');
	}
--FILE--
<?php
include "server_test.inc";

$file = <<<FL
\$key = 'abc';
\$b = uc_exists(\$key);
var_dump(\$b);
if (\$b) {
	\$\$key = uc_fetch(\$key);
	var_dump(\$\$key);
}
FL;

$args = array(
	'uc.enabled=1',
	'uc.enable_cli=1',
	'uc.preload_path=' . dirname(__FILE__) . '/data',
);

server_start($file, $args);

for ($i = 0; $i < 10; $i++) {
	run_test_simple();
}
echo 'done';

--XFAIL--
uc.preload_path not yet implemented
--EXPECT--
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
bool(true)
string(3) "123"
done
