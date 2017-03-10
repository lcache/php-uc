--TEST--
UC: uc_store/fetch with arrays with duplicate object
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php

$o = new stdClass();
$foo = array($o, $o);

var_dump($foo);

uc_store('foo',$foo);

$bar = uc_fetch('foo');
var_dump($foo);
// $bar[0] should be identical to $bar[1], and not a reference
var_dump($bar);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
array(2) {
  [0]=>
  object(stdClass)#1 (0) {
  }
  [1]=>
  object(stdClass)#1 (0) {
  }
}
array(2) {
  [0]=>
  object(stdClass)#1 (0) {
  }
  [1]=>
  object(stdClass)#1 (0) {
  }
}
array(2) {
  [0]=>
  object(stdClass)#2 (0) {
  }
  [1]=>
  object(stdClass)#2 (0) {
  }
}
===DONE===
