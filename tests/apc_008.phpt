--TEST--
UC: uc_cas test
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php
uc_store('foobar',2);
echo "\$foobar = 2\n";
echo "\$foobar == 1 ? 2 : 1 = ".(uc_cas('foobar', 1, 2)?"ok":"fail")."\n";
echo "\$foobar == 2 ? 1 : 2 = ".(uc_cas('foobar', 2, 1)?"ok":"fail")."\n";
echo "\$foobar = ".uc_fetch("foobar")."\n";

echo "\$f__bar == 1 ? 2 : 1 = ".(uc_cas('f__bar', 1, 2)?"ok":"fail")."\n";

uc_store('perfection', "xyz");
echo "\$perfection == 2 ? 1 : 2 = ".(uc_cas('perfection', 2, 1)?"ok":"epic fail")."\n";

echo "\$foobar = ".uc_fetch("foobar")."\n";
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
$foobar = 2
$foobar == 1 ? 2 : 1 = fail
$foobar == 2 ? 1 : 2 = ok
$foobar = 1
$f__bar == 1 ? 2 : 1 = ok
$perfection == 2 ? 1 : 2 = epic fail
$foobar = 1
===DONE===
