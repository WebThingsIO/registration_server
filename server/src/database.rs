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
use std::sync::mpsc::{Receiver, channel};
use std::thread;

macro_rules! sqlstr {
    ($row:ident, $index:expr) => (
        {
            let raw = $row.get::<i32, String>($index);
            if raw.is_empty() {
                None
            } else {
                Some(raw)
            }
        }
    )
}

pub struct DomainRecord;

impl DomainRecord {
    fn from_sql(row: Row) -> ServerInfo {
        ServerInfo {
            token: row.get(0),
            local_name: row.get(1),
            remote_name: row.get(2),
            dns_challenge: sqlstr!(row, 3),
            description: row.get(4),
            email: sqlstr!(row, 5),
            timestamp: row.get(6),
            reclamation_token: sqlstr!(row, 7),
        }
    }

    pub fn new(token: &str,
               local_name: &str,
               remote_name: &str,
               dns_challenge: Option<&str>,
               description: &str,
               email: Option<&str>,
               timestamp: i64,
               reclamation_token: Option<&str>)
               -> ServerInfo {
        macro_rules! str2sql {
            ($val:expr) => (
                if $val.is_some() {
                    Some($val.unwrap().to_owned())
                } else {
                    None
                }
            )
        }

        ServerInfo {
            local_name: local_name.to_owned(),
            remote_name: remote_name.to_owned(),
            token: token.to_owned(),
            dns_challenge: str2sql!(dns_challenge),
            description: description.to_owned(),
            email: str2sql!(email),
            timestamp: timestamp,
            reclamation_token: str2sql!(reclamation_token),
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
        let config = r2d2::Config::default();
        let manager = SqliteConnectionManager::new(path);
        let pool = r2d2::Pool::new(config, manager)
            .expect(&format!("Unable to open database at {}", path));

        let conn = pool.get().unwrap();

        macro_rules! index {
            ($table:expr, $index:expr) => (
                conn.execute(&format!("CREATE UNIQUE INDEX IF NOT EXISTS {}_{} ON {}({})",
                                      $table, $index, $table, $index), &[]).unwrap_or_else(|err| {
                                panic!("Unable to create the {}_{} index: {}", $table, $index, err);
                            });
            )
        }


        macro_rules! nouniqueindex {
            ($table:expr, $index:expr) => (
                conn.execute(&format!("CREATE INDEX IF NOT EXISTS {}_{} ON {}({})",
                                      $table, $index, $table, $index), &[]).unwrap_or_else(|err| {
                                panic!("Unable to create the {}_{} index: {}", $table, $index, err);
                            });
            )
        }
        // Create the domains table if needed.
        conn.execute("CREATE TABLE IF NOT EXISTS domains (
                      token             TEXT NOT NULL PRIMARY KEY,
                      local_name        TEXT NOT NULL,
                      remote_name       TEXT NOT NULL,
                      dns_challenge     TEXT NOT NULL,
                      description       TEXT NOT NULL,
                      email             TEXT NOT NULL,
                      timestamp         INTEGER,
                      reclamation_token TEXT NOT NULL)",
                     &[])
            .unwrap_or_else(|err| {
                                panic!("Unable to create the domains table: {}", err);
                            });

        index!("domains", "local_name");
        index!("domains", "remote_name");
        nouniqueindex!("domains", "timestamp");
        nouniqueindex!("domains", "email");

        // Create the email management table if needed.
        conn.execute("CREATE TABLE IF NOT EXISTS emails (
                      email  TEXT NOT NULL,
                      token  TEXT NOT NULL,
                      link   TEXT NOT NULL)",
                     &[])
            .unwrap_or_else(|err| {
                                panic!("Unable to create the email table: {}", err);
                            });
        index!("emails", "link");

        Database { pool: pool }
    }

    // Add a new email.
    // TODO: ensure that the token matches a domain token?
    pub fn add_email(&self,
                     email: &str,
                     token: &str,
                     link: &str)
                     -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let email = email.to_owned();
        let token = token.to_owned();
        let link = link.to_owned();
        thread::spawn(move || {
                          let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
                          sqltry!(conn.execute("INSERT INTO emails VALUES ($1, $2, $3)",
                                               &[&email, &token, &link]),
                                  tx);
                          tx.send(Ok(())).unwrap();
                      });

        rx
    }

    pub fn delete_email(&self, email: &str) -> Receiver<Result<i32, DatabaseError>> {
        self.execute_1param_sql("DELETE FROM emails WHERE email=$1",
                                SqlParam::Text(email.to_owned()))
    }

    pub fn get_email_by_link(&self,
                             link: &str)
                             -> Receiver<Result<(String, String), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let link = link.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT email, token from emails WHERE link=$1"),
                                   tx);
            let mut rows = sqltry!(stmt.query(&[&link]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok((row.get(0), row.get(1)))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }

        });

        rx
    }

    #[cfg(test)]
    pub fn get_email_by_token(&self,
                              token: &str)
                              -> Receiver<Result<(String, String), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let token = token.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT email, link from emails WHERE token=$1"),
                                   tx);
            let mut rows = sqltry!(stmt.query(&[&token]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok((row.get(0), row.get(1)))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }

        });

        rx
    }

    fn select_record(&self,
                     request: &str,
                     value: &str)
                     -> Receiver<Result<ServerInfo, DatabaseError>> {
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
        self.select_record("SELECT token, local_name, remote_name, dns_challenge, \
                            description, email, timestamp, reclamation_token \
                            FROM domains WHERE local_name=$1 or remote_name=$1",
                           name)
    }

    pub fn get_record_by_token(&self,
                               token: &str)
                               -> Receiver<Result<ServerInfo, DatabaseError>> {
        self.select_record("SELECT token, local_name, remote_name, dns_challenge, \
                            description, email, timestamp, reclamation_token \
                            FROM domains WHERE token=$1",
                           token)
    }

    pub fn add_record(&self, record: ServerInfo) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let record = record.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(conn.execute("INSERT INTO domains VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                                 &[&record.token,
                                   &record.local_name,
                                   &record.remote_name,
                                   &record.dns_challenge.unwrap_or("".to_owned()),
                                   &record.description,
                                   &record.email.unwrap_or("".to_owned()),
                                   &record.timestamp,
                                   &record.reclamation_token.unwrap_or("".to_owned())]),
                    tx);
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

            sqltry!(conn.execute("UPDATE domains SET dns_challenge=$1, timestamp=$2, \
                                  email=$3, description=$4, reclamation_token=$5 \
                                  WHERE (local_name=$6 OR remote_name=$7) AND token=$8",
                                 &[&record.dns_challenge.unwrap_or("".to_owned()),
                                   &record.timestamp,
                                   &record.email.unwrap_or("".to_owned()),
                                   &record.description,
                                   &record.reclamation_token.unwrap_or("".to_owned()),
                                   &record.local_name,
                                   &record.remote_name,
                                   &record.token]),
                    tx);
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

            sqltry!(conn.execute("UPDATE domains SET dns_challenge=$1, timestamp=$2, \
                                  email=$3, description=$4, reclamation_token=$5, token=$6 \
                                  WHERE local_name=$7 OR remote_name=$8",
                                 &[&record.dns_challenge.unwrap_or("".to_owned()),
                                   &record.timestamp,
                                   &record.email.unwrap_or("".to_owned()),
                                   &record.description,
                                   &record.reclamation_token.unwrap_or("".to_owned()),
                                   &record.token,
                                   &record.local_name,
                                   &record.remote_name]),
                    tx);
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    // Returns the number of rows affected.
    pub fn execute_1param_sql(&self,
                              request: &str,
                              value: SqlParam)
                              -> Receiver<Result<i32, DatabaseError>> {
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
        self.execute_1param_sql("DELETE FROM domains WHERE token=$1",
                                SqlParam::Text(token.to_owned()))
    }

    #[cfg(test)]
    pub fn flush(&self) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        thread::spawn(move || {
                          let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
                          sqltry!(conn.execute("DELETE FROM domains", &[]), tx);
                          sqltry!(conn.execute("DELETE FROM emails", &[]), tx);
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
    assert_eq!(db.get_record_by_name("test.example.org").recv().unwrap(),
               Err(DatabaseError::NoRecord));

    assert_eq!(db.get_record_by_token("test-token").recv().unwrap(),
               Err(DatabaseError::NoRecord));

    // Add a record without a DNS challenge.
    let no_challenge_record = DomainRecord::new("test-token",
                                                "local.test.example.org",
                                                "test.example.org",
                                                None,
                                                "Test Server",
                                                None,
                                                0,
                                                None);
    assert_eq!(db.add_record(no_challenge_record.clone()).recv().unwrap(),
               Ok(()));

    // Check that we can find it and that it matches our record.
    assert_eq!(db.get_record_by_name("test.example.org").recv().unwrap(),
               Ok(no_challenge_record.clone()));

    assert_eq!(db.get_record_by_token("test-token").recv().unwrap(),
               Ok(no_challenge_record.clone()));

    // Update the record to have challenge.
    let challenge_record = DomainRecord::new("test-token",
                                             "local.test.example.org",
                                             "test.example.org",
                                             Some("dns-challenge"),
                                             "Test Server",
                                             None,
                                             0,
                                             None);
    assert_eq!(db.update_record(challenge_record.clone()).recv().unwrap(),
               Ok(()));

    // Check that we can find it and that it matches our record.
    assert_eq!(db.get_record_by_name("test.example.org").recv().unwrap(),
               Ok(challenge_record.clone()));

    assert_eq!(db.get_record_by_token("test-token").recv().unwrap(),
               Ok(challenge_record.clone()));

    // Remove by token.
    assert_eq!(db.delete_record_by_token(&challenge_record.token)
                   .recv()
                   .unwrap(),
               Ok(1));

    assert_eq!(db.get_record_by_name(&challenge_record.local_name)
                   .recv()
                   .unwrap(),
               Err(DatabaseError::NoRecord));
}

#[test]
fn test_email() {
    let db = Database::new("domain_db_test_email.sqlite");

    // Start with an empty db.
    db.flush().recv().unwrap().expect("Flushing the db");

    let email = "test@example.com".to_owned();
    let link = "secret-link".to_owned();
    let token = "domain-token".to_owned();

    assert_eq!(db.get_email_by_link(&link).recv().unwrap(),
               Err(DatabaseError::NoRecord));
    assert_eq!(db.add_email(&email, &token, &link).recv().unwrap(), Ok(()));
    assert_eq!(db.get_email_by_link(&link).recv().unwrap(),
               Ok((email.clone(), token.clone())));
    assert_eq!(db.get_email_by_token(&token).recv().unwrap(),
               Ok((email.clone(), link.clone())));
    assert_eq!(db.delete_email(&email).recv().unwrap(), Ok(1));
    assert_eq!(db.get_email_by_link(&link).recv().unwrap(),
               Err(DatabaseError::NoRecord));
}
