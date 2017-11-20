// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Manages the SQL database that holds the list of registered domain names.
// Each record is made of the name, the private token, and the Let's Encrypt
// challenge value.

use types::ServerInfo;
use r2d2_sqlite::SqliteConnectionManager;
use r2d2;
use rusqlite::Row;
use rusqlite::Result as SqlResult;
use rusqlite::types::{ToSql, ToSqlOutput};
use std::sync::mpsc::{channel, Receiver};
use std::thread;

pub struct DomainRecord;

impl DomainRecord {
    fn from_sql(row: Row) -> ServerInfo {
        ServerInfo {
            name: row.get(0),
            account_id: row.get(1),
            token: row.get(2),
            description: row.get(3),
            timestamp: row.get(4),
            dns_challenge: row.get(5),
            reclamation_token: row.get(6),
            verification_token: row.get(7),
            verified: row.get(8),
        }
    }

    pub fn new(
        name: &str,
        account_id: i64,
        token: &str,
        description: &str,
        timestamp: i64,
        dns_challenge: &str,
        reclamation_token: &str,
        verification_token: &str,
        verified: bool,
    ) -> ServerInfo {
        ServerInfo {
            name: name.to_owned(),
            account_id: account_id,
            token: token.to_owned(),
            description: description.to_owned(),
            timestamp: timestamp,
            dns_challenge: dns_challenge.to_owned(),
            reclamation_token: reclamation_token.to_owned(),
            verification_token: verification_token.to_owned(),
            verified: verified,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DatabaseError {
    DbUnavailable,
    SQLError(String),
    NoRecord,
}

#[derive(Clone)]
pub struct Database {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

// try! like macro that sends back the error of a SQLite operation
// over the mpsc channel if needed.
macro_rules! sqltry {
    ($sql:expr, $tx:ident, $err:expr) => (
        match $sql {
            Err(_) => {
                $tx.send(Err($err)).unwrap();
                return;
            }
            Ok(value) => value,
        }
    );

    ($sql:expr, $tx:ident) => (
        match $sql {
            Err(err) => {
                $tx.send(Err(DatabaseError::SQLError(format!("{}", err)))).unwrap();
                return;
            }
            Ok(value) => value,
        }
    );
}

#[derive(Clone)]
pub enum SqlParam {
    Text(String),
    Integer(i64),
}

impl ToSql for SqlParam {
    fn to_sql(&self) -> SqlResult<ToSqlOutput> {
        match *self {
            SqlParam::Text(ref text) => text.to_sql(),
            SqlParam::Integer(ref number) => number.to_sql(),
        }
    }
}

impl Database {
    pub fn new(path: &str) -> Self {
        debug!("Opening database at {}", path);
        let manager = SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::new(manager).expect(&format!("Unable to open database at {}", path));

        let conn = pool.get().unwrap();

        macro_rules! index {
            ($table:expr, $index:expr) => (
                conn.execute(&format!("CREATE UNIQUE INDEX IF NOT EXISTS {}_{} ON {}({})",
                                      $table, $index, $table, $index), &[]).unwrap_or_else(|err| {
                                panic!("Unable to create the {}_{} index: {}", $table, $index, err);
                            });
            )
        }


        macro_rules! nonuniqueindex {
            ($table:expr, $index:expr) => (
                conn.execute(&format!("CREATE INDEX IF NOT EXISTS {}_{} ON {}({})",
                                      $table, $index, $table, $index), &[]).unwrap_or_else(|err| {
                                panic!("Unable to create the {}_{} index: {}", $table, $index, err);
                            });
            )
        }

        // Enable foreign key support.
        conn.execute("PRAGMA foreign_keys = ON", &[])
            .unwrap_or_else(|err| {
                panic!("Unable to enable foreign key support: {}", err);
            });

        // Create the email management table if needed.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS accounts (
                  id    INTEGER PRIMARY KEY,
                  email TEXT NOT NULL UNIQUE)",
            &[],
        ).unwrap_or_else(|err| {
                panic!("Unable to create the email table: {}", err);
            });

        index!("accounts", "email");

        // Create the domains table if needed.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domains (
                  name               TEXT NOT NULL UNIQUE PRIMARY KEY,
                  account_id         INTEGER NOT NULL,
                  token              TEXT NOT NULL,
                  description        TEXT NOT NULL,
                  timestamp          INTEGER NOT NULL,
                  dns_challenge      TEXT NOT NULL DEFAULT '',
                  reclamation_token  TEXT NOT NULL DEFAULT '',
                  verification_token TEXT NOT NULL DEFAULT '',
                  verified           BOOLEAN NOT NULL DEFAULT FALSE,
                  FOREIGN KEY(account_id) REFERENCES accounts(id)
                      ON UPDATE CASCADE ON DELETE CASCADE)",
            &[],
        ).unwrap_or_else(|err| {
                panic!("Unable to create the domains table: {}", err);
            });

        index!("domains", "name");
        nonuniqueindex!("domains", "timestamp");
        nonuniqueindex!("domains", "account_id");

        Database { pool: pool }
    }

    // Add a new email.
    pub fn add_email(&self, email: &str) -> Receiver<Result<(i64), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let email = email.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(
                conn.execute("INSERT INTO accounts (email) VALUES ($1)", &[&email]),
                tx
            );

            let mut stmt = sqltry!(conn.prepare("SELECT id FROM accounts WHERE email=$1"), tx);
            let mut rows = sqltry!(stmt.query(&[&email]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok(row.get(0))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }
        });

        rx
    }

    // Update an existing email.
    pub fn update_email(
        &self,
        email: &str,
        token: &str,
        link: &str,
    ) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let email = email.to_owned();
        let token = token.to_owned();
        let link = link.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(
                conn.execute(
                    "UPDATE accounts SET link = $1 WHERE email = $2 AND token = $3",
                    &[&link, &email, &token]
                ),
                tx
            );
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    pub fn delete_email(&self, email: &str) -> Receiver<Result<i32, DatabaseError>> {
        self.execute_1param_sql(
            "DELETE FROM accounts WHERE email=$1",
            SqlParam::Text(email.to_owned()),
        )
    }

    pub fn get_record_by_verification_token(
        &self,
        verification_token: &str,
    ) -> Receiver<Result<ServerInfo, DatabaseError>> {
        self.select_record(
            "SELECT name, account_id, token, description, timestamp, dns_challenge, \
             reclamation_token, verification_token, verified
             FROM domains WHERE verification_token=$1",
            verification_token,
        )
    }

    pub fn get_unknown_account_id(&self) -> Receiver<Result<(i64), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();

        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT id FROM accounts WHERE email=''"), tx);
            let mut rows = sqltry!(stmt.query(&[]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok(row.get(0))).unwrap();
            } else {
                // If the unknown account is not yet present, create it.
                sqltry!(
                    conn.execute("INSERT INTO accounts (email) VALUES ('')", &[]),
                    tx
                );

                // Now, get the account ID.
                let mut stmt = sqltry!(conn.prepare("SELECT id FROM accounts WHERE email=''"), tx);
                let mut rows = sqltry!(stmt.query(&[]), tx);
                if let Some(result_row) = rows.next() {
                    let row = sqltry!(result_row, tx);
                    tx.send(Ok(row.get(0))).unwrap();
                } else {
                    tx.send(Err(DatabaseError::NoRecord)).unwrap();
                }
            }
        });

        rx
    }

    pub fn get_email_by_account_id(
        &self,
        account_id: i64,
    ) -> Receiver<Result<(String), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT email FROM accounts WHERE id=$1"), tx);
            let mut rows = sqltry!(stmt.query(&[&account_id]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok(row.get(0))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }
        });

        rx
    }

    pub fn get_account_id_by_email(&self, email: &str) -> Receiver<Result<(i64), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let email = email.to_owned();

        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT id FROM accounts WHERE email=$1"), tx);
            let mut rows = sqltry!(stmt.query(&[&email]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok(row.get(0))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }
        });

        rx
    }

    fn select_record(
        &self,
        request: &str,
        value: &str,
    ) -> Receiver<Result<ServerInfo, DatabaseError>> {
        let (tx, rx) = channel();

        // Run the SQL command on a pooled thread.
        let pool = self.pool.clone();
        let value = value.to_owned();
        let request = request.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare(&request), tx);
            let mut rows = sqltry!(stmt.query(&[&value]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok(DomainRecord::from_sql(row))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }
        });

        rx
    }

    pub fn get_record_by_name(&self, name: &str) -> Receiver<Result<ServerInfo, DatabaseError>> {
        self.select_record(
            "SELECT name, account_id, token, description, timestamp, dns_challenge, \
             reclamation_token, verification_token, verified
             FROM domains WHERE name=$1",
            name,
        )
    }

    pub fn get_record_by_token(&self, token: &str) -> Receiver<Result<ServerInfo, DatabaseError>> {
        self.select_record(
            "SELECT name, account_id, token, description, timestamp, dns_challenge, \
             reclamation_token, verification_token, verified
             FROM domains WHERE token=$1",
            token,
        )
    }

    pub fn add_record(&self, record: ServerInfo) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let record = record.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(
                conn.execute(
                    "INSERT INTO domains VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    &[
                        &record.name,
                        &record.account_id,
                        &record.token,
                        &record.description,
                        &record.timestamp,
                        &record.dns_challenge,
                        &record.reclamation_token,
                        &record.verification_token,
                        &record.verified
                    ]
                ),
                tx
            );
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    pub fn update_record(&self, record: ServerInfo) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let record = record.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);

            sqltry!(
                conn.execute(
                    "UPDATE domains SET account_id=$1, description=$2, timestamp=$3, \
                     dns_challenge=$4, reclamation_token=$5, verification_token=$6, \
                     verified=$7 WHERE name=$8 AND token=$9",
                    &[
                        &record.account_id,
                        &record.description,
                        &record.timestamp,
                        &record.dns_challenge,
                        &record.reclamation_token,
                        &record.verification_token,
                        &record.verified,
                        &record.name,
                        &record.token
                    ]
                ),
                tx
            );
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    pub fn update_record_by_name(&self, record: ServerInfo) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let record = record.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);

            sqltry!(
                conn.execute(
                    "UPDATE domains SET account_id=$1, token=$2, description=$3, \
                     timestamp=$4, dns_challenge=$5, reclamation_token=$6, \
                     verification_token=$7, verified=$8 WHERE name=$9",
                    &[
                        &record.account_id,
                        &record.token,
                        &record.description,
                        &record.timestamp,
                        &record.dns_challenge,
                        &record.reclamation_token,
                        &record.verification_token,
                        &record.verified,
                        &record.name
                    ]
                ),
                tx
            );
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    // Returns the number of rows affected.
    pub fn execute_1param_sql(
        &self,
        request: &str,
        value: SqlParam,
    ) -> Receiver<Result<i32, DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let value = value.to_owned();
        let request = request.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let res = sqltry!(conn.execute(&request, &[&value]), tx);
            tx.send(Ok(res)).unwrap();
        });

        rx
    }

    pub fn delete_record_by_token(&self, token: &str) -> Receiver<Result<i32, DatabaseError>> {
        self.execute_1param_sql(
            "DELETE FROM domains WHERE token=$1",
            SqlParam::Text(token.to_owned()),
        )
    }

    pub fn delete_record_by_reclamation_token(
        &self,
        token: &str,
    ) -> Receiver<Result<i32, DatabaseError>> {
        self.execute_1param_sql(
            "DELETE FROM domains WHERE reclamation_token=$1",
            SqlParam::Text(token.to_owned()),
        )
    }

    #[cfg(test)]
    pub fn flush(&self) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(conn.execute("DELETE FROM domains", &[]), tx);
            sqltry!(conn.execute("DELETE FROM accounts", &[]), tx);
            tx.send(Ok(())).unwrap();
        });
        rx
    }
}

#[test]
fn test_domain_store() {
    let db = Database::new("domain_db_test_domains.sqlite");

    // Start with an empty db.
    db.flush().recv().unwrap().expect("Flushing the db");

    // Check that we don't find any record.
    assert_eq!(
        db.get_record_by_name("test.example.org").recv().unwrap(),
        Err(DatabaseError::NoRecord)
    );

    assert_eq!(
        db.get_record_by_token("test-token").recv().unwrap(),
        Err(DatabaseError::NoRecord)
    );

    // Add a record without a DNS challenge.
    let no_challenge_record = DomainRecord::new(
        "test.example.org",
        0,
        "test-token",
        "Test Server",
        0,
        "",
        "",
        "",
        false,
    );
    assert_eq!(
        db.add_record(no_challenge_record.clone()).recv().unwrap(),
        Ok(())
    );

    // Check that we can find it and that it matches our record.
    assert_eq!(
        db.get_record_by_name("test.example.org").recv().unwrap(),
        Ok(no_challenge_record.clone())
    );

    assert_eq!(
        db.get_record_by_token("test-token").recv().unwrap(),
        Ok(no_challenge_record.clone())
    );

    // Update the record to have challenge.
    let challenge_record = DomainRecord::new(
        "test.example.org",
        0,
        "test-token",
        "Test Server",
        0,
        "dns-challenge",
        "",
        "",
        false,
    );
    assert_eq!(
        db.update_record(challenge_record.clone()).recv().unwrap(),
        Ok(())
    );

    // Check that we can find it and that it matches our record.
    assert_eq!(
        db.get_record_by_name("test.example.org").recv().unwrap(),
        Ok(challenge_record.clone())
    );

    assert_eq!(
        db.get_record_by_token("test-token").recv().unwrap(),
        Ok(challenge_record.clone())
    );

    // Remove by token.
    assert_eq!(
        db.delete_record_by_token(&challenge_record.token)
            .recv()
            .unwrap(),
        Ok(1)
    );

    assert_eq!(
        db.get_record_by_name(&challenge_record.name)
            .recv()
            .unwrap(),
        Err(DatabaseError::NoRecord)
    );

    // Add a record without a reclamation token.
    let no_challenge_record = DomainRecord::new(
        "test.example.org",
        0,
        "test-token",
        "Test Server",
        0,
        "",
        "",
        "",
        false,
    );
    assert_eq!(
        db.add_record(no_challenge_record.clone()).recv().unwrap(),
        Ok(())
    );

    // Update the record by name to have a reclamation token.
    let challenge_record = DomainRecord::new(
        "test.example.org",
        0,
        "test-token",
        "Test Server",
        0,
        "",
        "test-reclamation-token",
        "",
        false,
    );
    assert_eq!(
        db.update_record_by_name(challenge_record.clone())
            .recv()
            .unwrap(),
        Ok(())
    );

    // Remove by reclamation token.
    assert_eq!(
        db.delete_record_by_reclamation_token(&challenge_record.reclamation_token)
            .recv()
            .unwrap(),
        Ok(1)
    );

    assert_eq!(
        db.get_record_by_name(&challenge_record.name)
            .recv()
            .unwrap(),
        Err(DatabaseError::NoRecord)
    );
}

#[test]
fn test_email() {
    let db = Database::new("domain_db_test_email.sqlite");

    // Start with an empty db.
    db.flush().recv().unwrap().expect("Flushing the db");

    let email = "test@example.com".to_owned();

    assert_eq!(
        db.get_account_id_by_email(&email).recv().unwrap(),
        Err(DatabaseError::NoRecord)
    );
    assert_eq!(db.add_email(&email).recv().unwrap(), Ok((1)));
    assert_eq!(db.get_account_id_by_email(&email).recv().unwrap(), Ok(1));
    assert_eq!(db.delete_email(&email).recv().unwrap(), Ok(1));
    assert_eq!(
        db.get_account_id_by_email(&email).recv().unwrap(),
        Err(DatabaseError::NoRecord)
    );
}
