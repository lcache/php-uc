--TEST--
UC: UCIterator Overwriting the ctor
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
class foobar extends UCIterator {
	public function __construct() {}
}
$obj = new foobar;
var_dump(
	$obj->rewind(),
	$obj->current(),
	$obj->key(),
	$obj->next(),
	$obj->valid(),
	$obj->getTotalHits(),
	$obj->getTotalSize(),
	$obj->getTotalCount(),
	uc_delete($obj)
);
?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)

