--TEST--
UC: uc_store/exists with long
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$foo = 42;
var_dump($foo);
$success = uc_store('foo',$foo);
var_dump($success);
$bar = uc_exists('foo');
var_dump($bar);
$bar = uc_fetch('foo');
var_dump($bar);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
int(42)
bool(true)
bool(true)
int(42)
===DONE===

