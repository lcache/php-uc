--TEST--
UC: UCIterator regex & chunk size & list
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php
$it = new UCIterator('/key[0-9]0/', APC_ITER_ALL, 1, APC_LIST_ACTIVE);
for($i = 0; $i < 41; $i++) {
  uc_store("key$i", "value$i");
}
foreach($it as $key=>$value) {
  $vals[$key] = $value['key'];
}
ksort($vals);
var_dump($vals);

?>
===DONE===
<?php exit(0); ?>
--EXPECT--
array(4) {
  ["key10"]=>
  string(5) "key10"
  ["key20"]=>
  string(5) "key20"
  ["key30"]=>
  string(5) "key30"
  ["key40"]=>
  string(5) "key40"
}
===DONE===
