--TEST--
UC: integer overflow consistency
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$key="testkey";
$i=PHP_INT_MAX;
uc_store($key, $i);
var_dump($j=uc_fetch($key));
var_dump($i==$j);

uc_inc($key, 1);
$i++;
var_dump($j=uc_fetch($key));
var_dump($i==$j);

$i=PHP_INT_MIN;
uc_store($key, $i);
uc_dec($key, 1);
$i--;
var_dump($j=uc_fetch($key));
var_dump($i==$j);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
int(%d)
bool(true)
float(%s)
bool(true)
float(%s)
bool(true)
===DONE===
