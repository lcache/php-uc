--TEST--
UC: uc_entry (recursion)
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$value = uc_entry("test", function($key){
	return uc_entry("child", function($key) {
		return "Hello World";
	});
});

var_dump($value, uc_entry("test", function($key){
	return "broken";
}), uc_entry("child", function(){
	return "broken";
}));
?>
===DONE===
<?php exit(0); ?>
--EXPECT--
string(11) "Hello World"
string(11) "Hello World"
string(11) "Hello World"
===DONE===
