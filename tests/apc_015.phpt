--TEST--
Copy failure should not create entry
--FILE--
<?php
try {
	uc_store('thing', function(){});
} catch(Exception $ex) {
}

var_dump(uc_exists('thing'));
--EXPECT--
bool(false)
