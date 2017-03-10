--TEST--
UC: uc_inc/uc_dec test
--SKIPIF--
<?php require_once(dirname(__FILE__) . '/skipif.inc'); ?>
--INI--
uc.enabled=1
uc.enable_cli=1
uc.file_update_protection=0
--FILE--
<?php
uc_store('foobar',2);
echo "\$foobar = 2 \n";
echo "\$foobar += 1 = ".uc_inc('foobar')."\n";
echo "\$foobar += 10 = ".uc_inc('foobar', 10)."\n";

echo "\$foobar -= 1 = ".uc_dec('foobar')."\n";
echo "\$foobar -= 10 = ".uc_dec('foobar',10)."\n";

echo "\$f__bar += 1 = ".(uc_inc('f__bar')?"ok":"fail")."\n";

uc_store('perfection', "xyz");
echo "\$perfection -= 1 = ".(uc_inc('perfection')?"ok":"epic fail")."\n";

$success = false;

echo "\$foobar += 1 = ".uc_inc('foobar', 1, $success)."\n";
echo "pass by ref success ". $success . "\n";
echo "\$foobar -= 1 = ".uc_dec('foobar', 1, $success)."\n";
echo "pass by ref success ". $success . "\n";

?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
$foobar = 2 
$foobar += 1 = 3
$foobar += 10 = 13
$foobar -= 1 = 12
$foobar -= 10 = 2
$f__bar += 1 = ok
$perfection -= 1 = epic fail
$foobar += 1 = 3
pass by ref success 1
$foobar -= 1 = 2
pass by ref success 1
===DONE===
