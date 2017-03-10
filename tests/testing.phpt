--TEST--
UC: uc_store/fetch with strings
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$foo = 'hello world';
var_dump($foo);
uc_store('foo',$foo);
$bar = uc_fetch('foo');
var_dump($bar);
$bar = 'nice';
var_dump($bar);
uc_store('foo\x00bar', $foo);
$bar = uc_fetch('foo\x00bar');
var_dump($bar);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
string(11) "hello world"
string(11) "hello world"
string(4) "nice"
string(11) "hello world"
===DONE===

