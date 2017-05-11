// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Manages the SQL database that holds the list of registered domain names.
// Each records is made of the name, the private token and the Let's Encrypt
// challenge value.

use std::sync::mpsc::{Receiver, channel};
use std::thread;

use r2d2_sqlite::SqliteConnectionManager;
use r2d2;
use rusqlite::Row;
use rusqlite::Result as SqlResult;
use rusqlite::types::{ToSql, ToSqlOutput};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DomainRecord {
    pub token: String,
    pub local_name: String,
    pub remote_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub timestamp: i64,
}

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

impl DomainRecord {
    fn from_sql(row: Row) -> Self {
        DomainRecord {
            token: row.get(0),
            local_name: row.get(1),
            remote_name: row.get(2),
            dns_challenge: sqlstr!(row, 3),
            local_ip: sqlstr!(row, 4),
            public_ip: sqlstr!(row, 5),
            description: row.get(6),
            email: sqlstr!(row, 7),
            timestamp: row.get(8),
        }
    }

    pub fn new(token: &str,
               local_name: &str,
               remote_name: &str,
               dns_challenge: Option<&str>,
               local_ip: Option<&str>,
               public_ip: Option<&str>,
               description: &str,
               email: Option<&str>,
               timestamp: i64)
               -> Self {
        macro_rules! str2sql {
            ($val:expr) => (
                if $val.is_some() {
                    Some($val.unwrap().to_owned())
                } else {
                    None
                }
            )
        }

        DomainRecord {
            local_name: local_name.to_owned(),
            remote_name: remote_name.to_owned(),
            token: token.to_owned(),
            dns_challenge: str2sql!(dns_challenge),
            local_ip: str2sql!(local_ip),
            public_ip: str2sql!(public_ip),
            description: description.to_owned(),
            email: str2sql!(email),
            timestamp: timestamp,
        }
    }
}

unsafe impl Send for DomainRecord {}
unsafe impl Sync for DomainRecord {}

#[derive(Debug)]
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
        let pool = r2d2::Pool::new(config, manager).expect(&format!("Unable to open database at {}",
                                                                    path));

        let conn = pool.get().unwrap();

        macro_rules! index {
            ($table:expr, $index:expr) => (
                conn.execute(&format!("CREATE UNIQUE INDEX IF NOT EXISTS {}_{} ON {}({})",
                                      $table, $index, $table, $index), &[]).unwrap_or_else(|err| {
                                panic!("Unable to create the {}_{} index: {}", $table, $index, err);
                            });
            )
        }

        // Create the domains table if needed.
        conn.execute("CREATE TABLE IF NOT EXISTS domains (
                      token         TEXT NOT NULL PRIMARY KEY,
                      local_name    TEXT NOT NULL,
                      remote_name   TEXT NOT NULL,
                      dns_challenge TEXT NOT NULL,
                      local_ip      TEXT NOT NULL,
                      public_ip     TEXT NOT NULL,
                      description   TEXT NOT NULL,
                      email         TEXT NOT NULL,
                      timestamp     INTEGER)",
                     &[])
            .unwrap_or_else(|err| {
                                panic!("Unable to create the domains table: {}", err);
                            });

        index!("domains", "local_name");
        index!("domains", "remote_name");
        index!("domains", "timestamp");
        index!("domains", "public_ip");
        index!("domains", "email");

        // Create the email management table if needed.
        conn.execute("CREATE TABLE IF NOT EXISTS emails (
                      email  TEXT NOT NULL PRIMARY KEY,
                      token  TEXT NOT NULL,
                      link   TEXT NOT NULL)",
                     &[])
            .unwrap_or_else(|err| {
                                panic!("Unable to create the email table: {}", err);
                            });

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

    pub fn select_email_by_link(&self, link: &str) -> Receiver<Result<i32, DatabaseError>> {
        self.execute_1param_sql("SELECT COUNT(*) FROM emails WHERE link=$1",
                                SqlParam::Text(link.to_owned()))
    }

    fn select_record(&self,
                     request: &str,
                     value: &str)
                     -> Receiver<Result<DomainRecord, DatabaseError>> {
        let (tx, rx) = channel();

        // Run the sql command on a pooled thread.
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

    fn select_records(&self,
                      request: &str,
                      value: &str)
                      -> Receiver<Result<Vec<DomainRecord>, DatabaseError>> {
        let (tx, rx) = channel();

        // Run the sql command on a pooled thread.
        let pool = self.pool.clone();
        let value = value.to_owned();
        let request = request.to_owned();
        thread::spawn(move || {
            let mut result = Vec::new();
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let mut stmt = sqltry!(conn.prepare(&request), tx);
            let mut rows = sqltry!(stmt.query(&[&value]), tx);
            while let Some(result_row) = rows.next() {
                let row = sqltry!(result_row, tx);
                result.push(DomainRecord::from_sql(row));
            }
            tx.send(Ok(result)).unwrap();
        });

        rx
    }

    pub fn get_records_by_public_ip(&self,
                                    public_ip: &str)
                                    -> Receiver<Result<Vec<DomainRecord>, DatabaseError>> {
        self.select_records("SELECT token, local_name, remote_name, dns_challenge, \
                            local_ip, public_ip, description, email, timestamp \
                            FROM domains WHERE public_ip=$1",
                            public_ip)
    }

    pub fn get_record_by_name(&self, name: &str) -> Receiver<Result<DomainRecord, DatabaseError>> {
        self.select_record("SELECT token, local_name, remote_name, dns_challenge, \
                            local_ip, public_ip, description, email, timestamp \
                            FROM domains WHERE local_name=$1 or remote_name=$1",
                           name)
    }

    pub fn get_record_by_token(&self,
                               token: &str)
                               -> Receiver<Result<DomainRecord, DatabaseError>> {
        self.select_record("SELECT token, local_name, remote_name, dns_challenge, \
                           local_ip, public_ip, description, email, timestamp \
                            FROM domains WHERE token=$1",
                           token)
    }

    pub fn add_record(&self, record: DomainRecord) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let record = record.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            sqltry!(conn.execute("INSERT INTO domains VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                                 &[&record.token,
                                   &record.local_name,
                                   &record.remote_name,
                                   &record.dns_challenge.unwrap_or("".to_owned()),
                                   &record.local_ip.unwrap_or("".to_owned()),
                                   &record.public_ip.unwrap_or("".to_owned()),
                                   &record.description,
                                   &record.email.unwrap_or("".to_owned()),
                                   &record.timestamp]),
                    tx);
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    pub fn update_record(&self, record: DomainRecord) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        let record = record.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);

            sqltry!(conn.execute("UPDATE domains SET dns_challenge=$1, local_ip=$2, \
                                  public_ip=$3, timestamp=$4 \
                                  WHERE (local_name=$5 OR remote_name=$6) AND token=$7",
                                 &[&record.dns_challenge.unwrap_or("".to_owned()),
                                   &record.local_ip.unwrap_or("".to_owned()),
                                   &record.public_ip.unwrap_or("".to_owned()),
                                   &record.timestamp,
                                   &record.local_name,
                                   &record.remote_name,
                                   &record.token]),
                    tx);
            tx.send(Ok(())).unwrap();
        });

        rx
    }

    // Evict records older than a given timestamp.
    // Returns the number of evicted records.
    pub fn evict_records(&self, timestamp: SqlParam) -> Receiver<Result<i32, DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        thread::spawn(move || {
            let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let res = sqltry!(conn.execute("UPDATE domains SET local_ip=$1, \
                    public_ip=$2, timestamp=$3 where timestamp<$4",
                                           &[&"", &"", &now, &timestamp]),
                              tx);
            tx.send(Ok(res)).unwrap();
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

    pub fn flush(&self) -> Receiver<Result<(), DatabaseError>> {
        let (tx, rx) = channel();

        let pool = self.pool.clone();
        thread::spawn(move || {
                          let conn = sqltry!(pool.get(), tx, DatabaseError::DbUnavailable);
                          sqltry!(conn.execute("DELETE FROM domains", &[]), tx);
                          tx.send(Ok(())).unwrap();
                      });
        rx
    }
}

#[test]
fn test_domain_store() {
    let db = Database::new("domain_db_test.sqlite");

    // Start with an empty db.
    db.flush().recv().unwrap().expect("Flushing the db");

    // Check that we don't find any record.
    match db.get_record_by_name("test.example.org")
              .recv()
              .unwrap() {
        Err(DatabaseError::NoRecord) => {}
        Err(err) => panic!("Should not find a record by name in an empty db. {:?}", err),
        _ => panic!("Should not find a record by name in an empty db."),
    }

    match db.get_record_by_token("test-token").recv().unwrap() {
        Err(DatabaseError::NoRecord) => {}
        _ => panic!("Should not find a record by token in an empty db."),
    }

    // Add a record without a dns challenge.
    let no_challenge_record = DomainRecord::new("test-token",
                                                "local.test.example.org",
                                                "test.example.org",
                                                None,
                                                None,
                                                None,
                                                "Test Server",
                                                None,
                                                0);
    db.add_record(no_challenge_record.clone())
        .recv()
        .unwrap()
        .expect("Adding the no_challenge record");

    // Check that we can find it and that it matches our record.
    match db.get_record_by_name("test.example.org")
              .recv()
              .unwrap() {
        Ok(record) => assert_eq!(record, no_challenge_record),
        Err(err) => panic!("Failed to find record by name: {:?}", err),
    }

    match db.get_record_by_token("test-token").recv().unwrap() {
        Ok(record) => assert_eq!(record, no_challenge_record),
        Err(err) => panic!("Failed to find record by token: {:?}", err),
    }

    // Update the record to have challenge.
    let challenge_record = DomainRecord::new("test-token",
                                             "local.test.example.org",
                                             "test.example.org",
                                             Some("dns-challenge"),
                                             None,
                                             None,
                                             "Test Server",
                                             None,
                                             0);
    db.update_record(challenge_record.clone())
        .recv()
        .unwrap()
        .expect("Updating the challenge record");

    // Check that we can find it and that it matches our record.
    match db.get_record_by_name("test.example.org")
              .recv()
              .unwrap() {
        Ok(record) => assert_eq!(record, challenge_record),
        Err(err) => panic!("Failed to find record by name: {:?}", err),
    }

    match db.get_record_by_token("test-token").recv().unwrap() {
        Ok(record) => assert_eq!(record, challenge_record),
        Err(err) => panic!("Failed to find record by token: {:?}", err),
    }

    // Remove by token.
    db.delete_record_by_token(&challenge_record.token)
        .recv()
        .unwrap()
        .expect("Should delete record by token");
    match db.get_record_by_name(&challenge_record.local_name)
              .recv()
              .unwrap() {
        Err(DatabaseError::NoRecord) => {}
        _ => panic!("Should not find this record anymore."),
    }
}
