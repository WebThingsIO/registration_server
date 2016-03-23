/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use rusqlite::{ self, Connection };
use std::time::{ SystemTime, UNIX_EPOCH };

#[cfg(test)]
fn get_db_environment() -> String {
    "./boxes_test.sqlite".to_string()
}

#[cfg(not(test))]
fn get_db_environment() -> String {
    "./boxes.sqlite".to_string()
}

#[derive(RustcEncodable, Debug)]
pub struct Record {
    pub public_ip: String,
    pub domain:    String,
    pub timestamp: i64 // i64 because of the database type.
}

fn escape(string: &str) -> String {
    // http://www.sqlite.org/faq.html#q14
    string.replace("'", "''")
}

pub enum FindFilter {
    PublicIp(String),
    PublicIpAndFingerprintDomain(String, String)
}

pub struct Db {
    // rusqlite::Connection already implements the Drop trait for the
    // inner connection so we don't need to manually close it. It will
    // be closed when the UsersDb instances go out of scope.
    connection: Connection
}

impl Db {
    pub fn new() -> Db {
        // TODO: manage errors.
        let connection = Connection::open(get_db_environment()).unwrap();
        connection.execute("CREATE TABLE IF NOT EXISTS boxes (
                public_ip TEXT NOT NULL,
                domain TEXT,
                timestamp INTEGER
            )", &[]).unwrap();

        Db {
            connection: connection
        }
    }

    pub fn seconds_from_epoch() -> i64 {
        let now = SystemTime::now();
        now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    #[cfg(test)]
    pub fn clear(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch(
            "DELETE FROM boxes;
             VACUUM;"
        )
    }

    // Looks for records for a given constraint.
    pub fn find(&self, filter: FindFilter) -> rusqlite::Result<Vec<Record>> {
        let mut stmt: rusqlite::Statement;

        let rows = match filter {
            FindFilter::PublicIp(public_ip) => {
                stmt = try!(
                    self.connection.prepare("SELECT * FROM boxes WHERE public_ip=$1")
                );
                try!(stmt.query(&[&escape(&public_ip)]))
            },
            FindFilter::PublicIpAndFingerprintDomain(public_ip, domain) => {
                stmt = try!(
                    self.connection.prepare("SELECT * FROM boxes WHERE (public_ip=$1 and domain=$2)")
                );
                try!(stmt.query(&[&escape(&public_ip), &escape(&domain)]))
            }
        };

        let mut records = Vec::new();
        for result_row in rows {
            let row = try!(result_row);
            records.push(Record {
                public_ip: row.get(0),
                domain: row.get(1),
                timestamp: row.get(2)
            });
        }
        Ok(records)
    }

    pub fn update(&self, record: Record) -> rusqlite::Result<i32> {
        self.connection.execute("UPDATE boxes
            SET public_ip=$1, domain=$2, timestamp=$3
            WHERE (public_ip=$4 AND domain=$5)",
            &[&record.public_ip, &record.domain,
              &record.public_ip, &record.domain])
    }

    pub fn add(&self, record: Record) -> rusqlite::Result<i32> {
        self.connection.execute("INSERT INTO boxes
            (public_ip, domain, timestamp)
            VALUES ($1, $2, $3)",
            &[&record.public_ip, &record.domain,
            &record.timestamp])
    }

    pub fn delete_older_than(&self, timestamp: i64) -> rusqlite::Result<i32> {
        self.connection.execute("DELETE FROM boxes WHERE timestamp < $1", &[&timestamp])
    }
}

#[test]
fn test_db() {
    let db = Db::new();

    // Look for a record, but the db is empty.
    match db.find(FindFilter::PublicIpAndFingerprintDomain("127.0.0.1".to_owned(), "<fingerprint>.knilxof.org".to_owned())) {
        Ok(vec) => { assert!(vec.is_empty()); },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }
    let now = Db::seconds_from_epoch();

    let mut r = Record {
        public_ip: "127.0.0.1".to_owned(),
        domain: "<fingerprint>.knilxof.org".to_owned(),
        timestamp: now
    };

    // Add this new record.
    match db.add(r) {
        Ok(n) => { assert_eq!(n, 1); }, // We expect one row to change.
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }
    // Check that we find it.
    match db.find(FindFilter::PublicIpAndFingerprintDomain("127.0.0.1".to_owned(), "<fingerprint>.knilxof.org".to_owned())) {
        Ok(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].timestamp, now);
        },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Add another record with the same public IP, but a different local one.
    r = Record {
        public_ip: "127.0.0.1".to_owned(),
        domain: "<another_fingerprint>.knilxof.org".to_owned(),
        timestamp: now
    };
    match db.add(r) {
        Ok(n) => { assert!(n == 1); }, // We expect one row to change.
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Now search for all the records with this public IP. Will find 2.
    match db.find(FindFilter::PublicIp("127.0.0.1".to_owned())) {
        Ok(records) => {
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].domain, "<fingerprint>.knilxof.org");
            assert_eq!(records[1].domain, "<another_fingerprint>.knilxof.org");
        },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Fake travelling in the future, and evict both records.
    match db.delete_older_than(now + 2) {
        Ok(count) => assert_eq!(count, 2),
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }
    db.clear().unwrap();
}
