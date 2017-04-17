<?php

// To run from the CLI:
// php -d extension=modules/uc.so long.php

var_dump(uc_size());
uc_store('thing', 'hello');
uc_fetch('thing');
uc_fetch(['thing']);

uc_delete('thing');

