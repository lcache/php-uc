--TEST--
UC: store array of references
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.serializer=php
--FILE--
<?php
$_items = [
	'key1' => 'value1',
	'key2' => 'value2',
];
$items = [];
foreach($_items as $k => $v) {
	$items["prefix_$k"] = &$v;
}
var_dump(uc_store($items));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
array(0) {
}
===DONE===
