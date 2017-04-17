<?php

// Under GDB with symbols:
// sudo dnf update --enable=updates-debuginfo
// gdb --args php -d extension=modules/uc.so trace.php
// (gdb) break uc_storage::store

while(true) {
    uc_store('key', 1);
}

