--TEST--
gh bug #168
--INI--
uc.enabled=1
uc.enable_cli=1
--FILE--
<?php
uc_store('prop', 'A');

var_dump($prop = uc_fetch('prop'));

uc_store('prop', ['B']);

var_dump(uc_fetch('prop'), $prop);

uc_store('thing', ['C']);

var_dump(uc_fetch('prop'), $prop);
--EXPECT--
string(1) "A"
array(1) {
  [0]=>
  string(1) "B"
}
string(1) "A"
array(1) {
  [0]=>
  string(1) "B"
}
string(1) "A"

