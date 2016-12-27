# php-uc
A PHP extension providing an APCu-compatible API sufficient for LCache and built on LevelDB.

## Building

1. Acquire and build RocksDB:

        sudo dnf install gcc-c++ gflags snappy-devel zlib-devel bzip2-devel
        cd ~/Sandbox/
        RELEASE=4.13
        wget https://github.com/facebook/rocksdb/archive/v$RELEASE.tar.gz
        tar xzf https://github.com/facebook/rocksdb/archive/v$RELEASE.tar.gz
        cd rocksdb-$RELEASE
        make shared_lib  # Would be better to make this static.
    
1. Build PHP User Cache:

        phpize
        ./configure --with-rocksdb=$HOME/Sandbox/rocksdb-$RELEASE
        
