--TEST--
UC: uc_size
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$s = uc_size();
var_dump($s);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
int(0)
===DONE===

