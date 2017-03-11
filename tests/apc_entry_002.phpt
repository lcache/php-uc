--TEST--
UC: uc_entry (exception)
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
$value = uc_entry("test", function($key){
	throw new Exception($key);
});
?>
--XFAIL--
uc_entry not yet implemented
--EXPECTF--
Fatal error: Uncaught Exception: test in %s:3
Stack trace:
#0 [internal function]: {closure}('test')
#1 %s(4): uc_entry('test', Object(Closure))
#2 {main}
  thrown in %s on line 3
