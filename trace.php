<?php

// Under GDB with symbols:
// sudo dnf update --enable=updates-debuginfo
// gdb --args php -d extension=modules/uc.so trace.php
// (gdb) break uc_storage::store
// (gdb) run

uc_store('foobar',2);
uc_inc('foobar');
uc_inc('foobar', 10);

