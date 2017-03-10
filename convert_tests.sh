#!/bin/sh
sed -i 's/apc\.\([a-z_]*\)=/uc\.\1=/g' tests/*.phpt
sed -i 's/apcu\.\([a-z_]*\)=/uc\.\1=/g' tests/*.phpt
sed -i 's/apc_/uc_/g' tests/*.phpt
sed -i 's/apcu_/uc_/g' tests/*.phpt
sed -i 's/APCIterator/UCIterator/g' tests/*.phpt
sed -i 's/APCuIterator/UCIterator/g' tests/*.phpt
sed -i 's/APC: /UC: /' tests/*.phpt

