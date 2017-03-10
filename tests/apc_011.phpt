--TEST--
UC: uc_fetch resets array pointers
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php
$items = array('bar', 'baz');

uc_store('test', $items);

$back = uc_fetch('test');

var_dump(current($back));
var_dump(current($back));

?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
string(3) "bar"
string(3) "bar"
===DONE===
