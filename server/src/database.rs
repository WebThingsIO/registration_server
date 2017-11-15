// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Manages the SQL database that holds the list of registered domain names.
// Each record is made of the name, the private token, and the Let's Encrypt
// challenge value.

use types::{PendingDomain, ServerInfo};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2;
use rusqlite::Row;
use rusqlite::Result as SqlResult;
use rusqlite::types::{ToSql, ToSqlOutput};
use serde_json;
use std::sync::mpsc::{channel, Receiver};
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
            name: row.get(0),
            token: row.get(1),
            dns_challenge: sqlstr!(row, 2),
            description: row.get(3),
            email: sqlstr!(row, 4),
            timestamp: row.get(5),
            reclamation_token: sqlstr!(row, 6),
        }
    }

    pub fn new(
        name: &str,
        token: &str,
        dns_challenge: Option<&str>,
        description: &str,
        email: Option<&str>,
        timestamp: i64,
        reclamation_token: Option<&str>,
    ) -> ServerInfo {
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
            name: name.to_owned(),
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
            "CREATE TABLE IF NOT EXISTS emails (
                  email   TEXT NOT NULL UNIQUE PRIMARY KEY,
                  pending TEXT NOT NULL)",
            &[],
        ).unwrap_or_else(|err| {
                panic!("Unable to create the email table: {}", err);
            });

        // Create the domains table if needed.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domains (
                  name              TEXT NOT NULL UNIQUE PRIMARY KEY,
                  token             TEXT NOT NULL,
                  dns_challenge     TEXT NOT NULL,
                  description       TEXT NOT NULL,
                  email             TEXT NOT NULL,
                  timestamp         INTEGER NOT NULL,
                  reclamation_token TEXT NOT NULL,
                  FOREIGN KEY(email) REFERENCES emails(email) ON UPDATE CASCADE ON DELETE CASCADE)",
            &[],
        ).unwrap_or_else(|err| {
                panic!("Unable to create the domains table: {}", err);
            });

        index!("domains", "name");
        nonuniqueindex!("domains", "timestamp");
        nonuniqueindex!("domains", "email");

        Database { pool: pool }
    }

    // Add a new email.
    // TODO: ensure that the token matches a domain token?
    pub fn add_email(
        &self,
        email: &str,
        token: &str,
        link: &str,
    ) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let email = email.to_owned();

        // Convert the list of pending domain verifications to JSON.
        let pending = vec![
            PendingDomain {
                token: token.to_owned(),
                link: link.to_owned(),
            },
        ];
        let pending = serde_json::to_string(&pending).unwrap();

        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(
                conn.execute("INSERT INTO emails VALUES ($1, $2)", &[&email, &pending]),
                tx
            );
            tx.send(Ok(())).unwrap();
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

        let result = self.get_email_by_email(&email);
        let pool = self.pool.clone();
        let email = email.to_owned();
        let token = token.to_owned();
        let link = link.to_owned();

        thread::spawn(move || match result.recv().unwrap() {
            Ok(record) => {
                // Found a record with this email. Get its list of pending verifications.
                let mut pending: Vec<PendingDomain> = match serde_json::from_str(&record.1) {
                    Ok(val) => val,
                    Err(_) => Vec::new(),
                };

                let mut found = false;
                for i in &mut pending {
                    // If the token is already in the list, update the verification link.
                    if i.token == token {
                        i.link = link.to_owned();
                        found = true;
                        break;
                    }
                }

                // Add the new verification if the token wasn't already found.
                if !found {
                    pending.push(PendingDomain {
                        token: token.to_owned(),
                        link: link.to_owned(),
                    });
                }

                // Convert the list of pending domain verifications to JSON.
                let pending = serde_json::to_string(&pending).unwrap();
                let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
                sqltry!(
                    conn.execute(
                        "UPDATE emails SET pending=$1 WHERE email=$2",
                        &[&pending, &email]
                    ),
                    tx
                );
                tx.send(Ok(())).unwrap();
            }
            Err(_) => {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }
        });

        rx
    }

    pub fn delete_pending_domain_from_email(
        &self,
        email: &str,
        token: &str,
    ) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let result = self.get_email_by_email(&email);
        let pool = self.pool.clone();
        let email = email.to_owned();
        let token = token.to_owned();

        thread::spawn(move || match result.recv().unwrap() {
            Ok(record) => {
                // Found a record with this email. Get its list of pending verifications.
                let pending = serde_json::from_str(&record.1);
                if pending.is_err() {
                    // Pending list is empty, nothing to do.
                    tx.send(Ok(())).unwrap();
                    return;
                }

                let mut pending: Vec<PendingDomain> = pending.unwrap();
                let mut index = pending.len() + 1;

                // Look for the token in the pending list.
                for (i, item) in pending.iter().enumerate() {
                    if item.token == token {
                        index = i;
                        break;
                    }
                }

                if index > pending.len() {
                    // Token not found in pending list, nothing to do.
                    tx.send(Ok(())).unwrap();
                    return;
                }

                // Remove this token from the list.
                pending.remove(index);

                // Convert the list of pending domain verifications to JSON.
                let pending = serde_json::to_string(&pending).unwrap();
                let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
                sqltry!(
                    conn.execute(
                        "UPDATE emails SET pending=$1 WHERE email=$2",
                        &[&pending, &email]
                    ),
                    tx
                );
                tx.send(Ok(())).unwrap();
            }
            Err(_) => {
                // Nothing to delete.
                tx.send(Ok(())).unwrap();
            }
        });

        rx
    }

    pub fn get_email_by_email(
        &self,
        email: &str,
    ) -> Receiver<Result<(String, String), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let email = email.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(
                conn.prepare("SELECT email, pending FROM emails WHERE email=$1"),
                tx
            );
            let mut rows = sqltry!(stmt.query(&[&email]), tx);
            if let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                tx.send(Ok((row.get(0), row.get(1)))).unwrap();
            } else {
                tx.send(Err(DatabaseError::NoRecord)).unwrap();
            }
        });

        rx
    }

    pub fn get_email_by_link(
        &self,
        link: &str,
    ) -> Receiver<Result<(String, String), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let link = link.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT email, pending FROM emails"), tx);
            let mut rows = sqltry!(stmt.query(&[]), tx);

            // Since the links are nested into a column, we have to loop over every row.
            'outer: loop {
                if let Some(result_row) = rows.next() {
                    let row = sqltry!(result_row, tx);
                    let email: String = row.get(0);
                    let pending: String = row.get(1);
                    let result = serde_json::from_str(&pending);
                    if result.is_err() {
                        continue;
                    }

                    // Look for the link in this record's list of pending verifications.
                    let pending: Vec<PendingDomain> = result.unwrap();
                    'inner: for i in pending {
                        if i.link == link {
                            tx.send(Ok((email, i.token))).unwrap();
                            break 'outer;
                        }
                    }
                } else {
                    tx.send(Err(DatabaseError::NoRecord)).unwrap();
                    break;
                }
            }
        });

        rx
    }

    pub fn get_email_by_token(
        &self,
        token: &str,
    ) -> Receiver<Result<(String, String), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let token = token.to_owned();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare("SELECT email, pending FROM emails"), tx);
            let mut rows = sqltry!(stmt.query(&[]), tx);

            // Since the tokens are nested into a column, we have to loop over every row.
            'outer: loop {
                if let Some(result_row) = rows.next() {
                    let row = sqltry!(result_row, tx);
                    let email: String = row.get(0);
                    let pending: String = row.get(1);
                    let result = serde_json::from_str(&pending);
                    if result.is_err() {
                        continue;
                    }

                    // Look for the token in this record's list of pending verifications.
                    let pending: Vec<PendingDomain> = result.unwrap();
                    'inner: for i in pending {
                        if i.token == token {
                            tx.send(Ok((email, i.link))).unwrap();
                            break 'outer;
                        }
                    }
                } else {
                    tx.send(Err(DatabaseError::NoRecord)).unwrap();
                    break;
                }
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
            "SELECT  name, token, dns_challenge, \
             description, email, timestamp, reclamation_token \
             FROM domains WHERE name=$1",
            name,
        )
    }

    pub fn get_record_by_token(&self, token: &str) -> Receiver<Result<ServerInfo, DatabaseError>> {
        self.select_record(
            "SELECT name, token, dns_challenge, \
             description, email, timestamp, reclamation_token \
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
                    "INSERT INTO domains VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    &[
                        &record.name,
                        &record.token,
                        &record.dns_challenge.unwrap_or("".to_owned()),
                        &record.description,
                        &record.email.unwrap_or("".to_owned()),
                        &record.timestamp,
                        &record.reclamation_token.unwrap_or("".to_owned())
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
                    "UPDATE domains SET dns_challenge=$1, timestamp=$2, \
                     email=$3, description=$4, reclamation_token=$5 \
                     WHERE name=$6 AND token=$7",
                    &[
                        &record.dns_challenge.unwrap_or("".to_owned()),
                        &record.timestamp,
                        &record.email.unwrap_or("".to_owned()),
                        &record.description,
                        &record.reclamation_token.unwrap_or("".to_owned()),
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
                    "UPDATE domains SET dns_challenge=$1, timestamp=$2, \
                     email=$3, description=$4, reclamation_token=$5, token=$6 \
                     WHERE name=$7",
                    &[
                        &record.dns_challenge.unwrap_or("".to_owned()),
                        &record.timestamp,
                        &record.email.unwrap_or("".to_owned()),
                        &record.description,
                        &record.reclamation_token.unwrap_or("".to_owned()),
                        &record.token,
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
        "test-token",
        None,
        "Test Server",
        None,
        0,
        None,
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
        "test-token",
        Some("dns-challenge"),
        "Test Server",
        None,
        0,
        None,
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
        "test-token",
        None,
        "Test Server",
        None,
        0,
        None,
    );
    assert_eq!(
        db.add_record(no_challenge_record.clone()).recv().unwrap(),
        Ok(())
    );

    // Update the record by name to have a reclamation token.
    let challenge_record = DomainRecord::new(
        "test.example.org",
        "test-token",
        None,
        "Test Server",
        None,
        0,
        Some("test-reclamation-token"),
    );
    assert_eq!(
        db.update_record_by_name(challenge_record.clone())
            .recv()
            .unwrap(),
        Ok(())
    );

    // Remove by reclamation token.
    assert_eq!(
        db.delete_record_by_reclamation_token(&challenge_record.reclamation_token.unwrap())
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
    let link = "secret-link".to_owned();
    let token = "domain-token".to_owned();

    assert_eq!(
        db.get_email_by_link(&link).recv().unwrap(),
        Err(DatabaseError::NoRecord)
    );
    assert_eq!(db.add_email(&email, &token, &link).recv().unwrap(), Ok(()));
    assert_eq!(
        db.get_email_by_link(&link).recv().unwrap(),
        Ok((email.clone(), token.clone()))
    );
    assert_eq!(
        db.get_email_by_token(&token).recv().unwrap(),
        Ok((email.clone(), link.clone()))
    );
    assert_eq!(
        db.delete_pending_domain_from_email(&email, &token)
            .recv()
            .unwrap(),
        Ok(())
    );
    assert_eq!(
        db.get_email_by_link(&link).recv().unwrap(),
        Err(DatabaseError::NoRecord)
    );
}
