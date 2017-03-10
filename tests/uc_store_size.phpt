--TEST--
UC: uc_store/size with string
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$foo = 'hello world';
var_dump($foo);
uc_store('foo',$foo);
$bar = uc_size();
var_dump($bar);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
string(11) "hello world"
int(1)
===DONE===

