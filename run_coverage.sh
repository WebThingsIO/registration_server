#!/bin/bash

set -e

# Set up databases
for database in domain_db_test_domains domain_db_test_email domain_db_test_pdns domain_db_test_routes; do
    db_path="./${database}.sqlite"
    rm -f "${db_path}" >/dev/null 2>&1 || true

    diesel --database-url "${db_path}" setup --migration-dir "migrations/sqlite"
    diesel --database-url "${db_path}" migration --migration-dir "migrations/sqlite" run
done

# Generate test binary
cargo clean
cargo test --no-run --features sqlite

# Download and build kcov
wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
tar xzf master.tar.gz
cd kcov-master
mkdir build
cd build
cmake ..
make
make install DESTDIR=../../kcov-build
cd ../..
rm -rf kcov-master

# Run kcov on the test binary
for file in target/debug/main-*[^\.d] target/debug/registration_server-*[^\.d]; do
    mkdir -p "target/cov/$(basename $file)"
    ./kcov-build/usr/local/bin/kcov \
        --exclude-pattern=/.cargo,/usr/lib \
        --verify "target/cov/$(basename $file)" \
        "$file"
done

# Upload results
bash <(curl -s https://codecov.io/bash)
