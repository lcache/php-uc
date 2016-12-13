# php-uc
A PHP extension providing an APCu-compatible API sufficient for LCache and built on LevelDB.

## Building

### RocksDB

    sudo dnf install gcc-c++ gflags snappy-devel zlib-devel bzip2-devel
    RELEASE=4.13
    wget https://github.com/facebook/rocksdb/archive/v$RELEASE.tar.gz
    tar xzf https://github.com/facebook/rocksdb/archive/v$RELEASE.tar.gz
    cd rocksdb-$RELEASE
    make static_lib
    
