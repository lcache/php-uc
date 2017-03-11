# php-uc
A PHP extension providing an APCu-compatible API built on Boost Interprocess.

## Building

1. Acquire build dependencies (Fedora instructions listed here):

        sudo dnf install gcc-c++ boost boost-devel boost-interprocess boost-atomic

1. Build and install the PHP User Cache:

        phpize
        ./configure --enable-uc
        make
        make test
        sudo make install

## Testing

After running `./configure`, you can run tests:

* Basic: `make test`
* With Valgrind: `make test TESTS="-m"`
