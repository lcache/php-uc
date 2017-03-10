--TEST--
UC: uc_exists
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$kyes = "testkey";
$kno  = "keytest";
uc_store($kyes, 1);
var_dump(uc_exists($kyes));
var_dump(uc_exists($kno));
var_dump(uc_exists([$kyes, $kno]));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
bool(true)
bool(false)
array(1) {
  ["testkey"]=>
  bool(true)
}
===DONE===
