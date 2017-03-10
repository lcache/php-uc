--TEST--
UC: uc_store/fetch with arrays of objects 
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php

$foo = array(new stdclass(), new stdclass());

var_dump($foo);

uc_store('foo',$foo);

$bar = uc_fetch('foo');
var_dump($foo);
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
  object(stdClass)#2 (0) {
  }
}
array(2) {
  [0]=>
  object(stdClass)#1 (0) {
  }
  [1]=>
  object(stdClass)#2 (0) {
  }
}
array(2) {
  [0]=>
  object(stdClass)#3 (0) {
  }
  [1]=>
  object(stdClass)#4 (0) {
  }
}
===DONE===
