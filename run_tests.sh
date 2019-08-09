#!/bin/bash

set -e

for db_type in mysql postgres sqlite; do
    for database in domain_db_test_domains domain_db_test_email domain_db_test_pdns domain_db_test_routes; do
        if [ "${db_type}" = "mysql" ]; then
            db_path="mysql://root@127.0.0.1/${database}"
            mysql -uroot -e "drop database ${database}" >/dev/null 2>&1 || true
        elif [ "${db_type}" = "postgres" ]; then
            db_path="postgres://postgres@127.0.0.1/${database}"
            dropdb -U postgres "${database}" >/dev/null 2>&1 || true
        elif [ "${db_type}" = "sqlite" ]; then
            db_path="./${database}.sqlite"
            rm -f "${db_path}" >/dev/null 2>&1 || true
        else
            echo "Database type is invalid, must be: mysql/postgres/sqlite"
            exit 1
        fi

        diesel --database-url "${db_path}" setup --migration-dir "migrations/${db_type}"
        diesel --database-url "${db_path}" migration --migration-dir "migrations/${db_type}" run
    done

    echo
    echo "Testing ${db_type}"
    cargo test --features "${db_type}" "$@"
done
