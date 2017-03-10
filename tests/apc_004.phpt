--TEST--
UC: uc_store/fetch with bools 
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php

$foo = false;
var_dump($foo);     /* false */
uc_store('foo',$foo);
//$success = "some string";

$bar = uc_fetch('foo', $success);
var_dump($foo);     /* false */
var_dump($bar);     /* false */
var_dump($success); /* true  */

$bar = uc_fetch('not foo', $success);
var_dump($foo);     /* false */
var_dump($bar);     /* false */
var_dump($success); /* false */

?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
bool(true)
bool(false)
bool(false)
bool(false)
===DONE===
