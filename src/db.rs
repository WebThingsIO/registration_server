/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use redis::{ Client, cmd, Connection, ConnectionAddr, ConnectionInfo,
             pipe, RedisResult };
use std::time::Duration;
use std::thread::sleep;

static RECORD_TTL: i32 = 2 * 60; // 2 minutes

#[derive(RustcEncodable, Debug)]
pub struct Record {
    pub public_ip: String,
    pub client:    String,
    pub message:   String,
}

pub struct Db {
    connection: Connection
}

impl Db {
    pub fn new(db_host: String,
               db_port: u16,
               db_password: Option<String>) -> Db {
        let client = Client::open(ConnectionInfo {
            addr: Box::new(ConnectionAddr::Tcp(db_host.clone(), db_port)),
            db: 0,
            passwd: db_password.clone()
        }).unwrap();

        loop {
            match client.get_connection() {
                Err(err) => {
                    if err.is_connection_refusal() {
                        warn!("Could not connect: {} (Will retry)", err);
                        sleep(Duration::from_millis(1));
                    } else {
                        panic!("Could not connect: {}", err);
                    }
                },
                Ok(connection) => {
                    return Db {
                        connection: connection
                    }
                },
            }
        }
    }

    ///
    /// Add or update a DB record.
    /// We keep a set with the record's public IP as key containing the list
    /// of client IDs registered for this public IP and we store a message
    /// per each "publicIP:clientID" tuple.
    /// For example:
    ///
    /// "88.22.170.96": [
    ///     "e7ce02eaa73da35bddea00c82124c7fbbe49b731",
    ///     "2b3e83cca3ee12c8b41d86bfeca6034ea8cb9056"
    /// ]
    ///
    /// "88.22.170.96:e7ce02eaa73da35bddea00c82124c7fbbe49b731": "message1"
    /// "88.22.170.96:2b3e83cca3ee12c8b41d86bfeca6034ea8cb9056": "message2"
    ///
    /// Each "publicIP:clientID" tuple has a ttl of 2 minutes.
    ///
    pub fn set(&self, record: Record) -> RedisResult<()> {
        let key = format!("{}:{}", record.public_ip, record.client);

        // We need to start watching the keys we care about (public_ip and
        // public_ip:client) so that our exec fails if the key changes.
        let _: () = try!(
            cmd("WATCH").arg(key.clone())
                        .arg(record.public_ip.clone())
                        .query(&self.connection)
        );

        // We check if there's already an entry for this public IP.
        let is_member: isize = try!(
            cmd("SISMEMBER").arg(record.public_ip.clone())
                            .arg(record.client.clone())
                            .query(&self.connection)
        );

        if is_member == 0 {
            // If there is no previous entry for this public IP, we add one
            // and add the message corresponding to this key (IP:user tuple)
            info!("{} is not a member of {} yet",
                  record.client.clone(), record.public_ip.clone());
            let _: () = try!(
                pipe().atomic()
                      .cmd("SADD").arg(record.public_ip.clone())
                                  .arg(record.client.clone())
                                  .ignore()
                      .cmd("SET").arg(key.clone())
                                 .arg(record.message.clone())
                                 .query(&self.connection)
            );
        } else {
            // Otherwise, we just update the message from the existing
            // entry.
            info!("{} is already a member of {}",
                  record.client.clone(), record.public_ip.clone());
            let _: () = try!(
                cmd("SET").arg(key.clone())
                          .arg(record.message.clone())
                          .query(&self.connection)
            );
        }

        // And set the TTL of the message.
        // The entry in the list of clients for this public IP will be
        // cleaned up during the .get call. It does no harm to keep it
        // around until that point.
        let _: () = try!(
            cmd("EXPIRE").arg(key.clone())
                         .arg(RECORD_TTL) // 2 min.
                         .query(&self.connection)
        );

        Ok(())
    }

    ///
    /// Get the registration entries for a given public IP.
    ///
    pub fn get(&self, public_ip: String) -> RedisResult<Vec<Record>> {
        let _: () = try!(
            cmd("WATCH").arg(public_ip.clone())
                        .query(&self.connection)
        );

        // Get the clients for the given public IP.
        let members: Vec<String> = try!(
            cmd("SMEMBERS").arg(public_ip.clone())
                           .query(&self.connection)
        );

        info!("Members of {}: {:?}", public_ip.clone(), members.clone());

        let mut result = Vec::new();

        // For each client we get the associated message.
        for member in members {
            let key = format!("{}:{}", public_ip.clone(), member);
            info!("Key {}", key.clone());
            match cmd("GET").arg(key.clone())
                                    .query(&self.connection) {
                Ok(message) => {
                    info!("Message for {}: {}", key.clone(), message);

                    result.push(Record {
                        public_ip: public_ip.clone(),
                        client: member.clone(),
                        message: message
                    });
                },
                Err(_) => {
                    // Remove the client id from the list of clients of this public
                    // IP that has no associated message.
                    info!("Removing {} from {}", member.clone(), public_ip.clone());
                    let _: () = try!(
                        cmd("SREM").arg(public_ip.clone())
                                   .arg(member.clone())
                                   .query(&self.connection)
                    );
                }
            };
        }

        Ok(result)
    }

    #[cfg(test)]
    pub fn flush(&self) -> RedisResult<()> {
        let _: () = try!(
            cmd("FLUSHDB").query(&self.connection)
        );

        Ok(())
    }
}

#[test]
fn test_db() {
    use super::db_test_context::TestContext;

    let ctx = TestContext::new();
    let db = ctx.db;

    // Look for a record, but the db is empty.
    match db.get("127.0.0.1".to_owned()) {
        Ok(vec) => { assert!(vec.is_empty()); },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    };

    let mut r = Record {
        public_ip: "127.0.0.1".to_owned(),
        message: "<message>".to_owned(),
        client: "<fingerprint>".to_owned()
    };

    // Add this new record.
    match db.set(r) {
        Ok(_) => { assert!(true); },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Check that we find it.
    match db.get("127.0.0.1".to_owned()) {
        Ok(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].message, "<message>");
        },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Add another record with the same public IP, but a different local one.
    r = Record {
        public_ip: "127.0.0.1".to_owned(),
        message: "<another_message>".to_owned(),
        client:  "<another_fingerprint>".to_owned()
    };

    match db.set(r) {
        Ok(_) => { assert!(true); },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Now search for all the records with this public IP. Will find 2.
    match db.get("127.0.0.1".to_owned()) {
        Ok(records) => {
            assert_eq!(records.len(), 2);
            assert!(records[0].message == "<another_message>" ||
                    records[0].message == "<message>");
            assert!(records[1].message == "<another_message>" ||
                    records[1].message == "<message>");
            assert!(records[0].client ==  "<another_fingerprint>" ||
                    records[0].client == "<fingerprint>");
            assert!(records[1].client ==  "<another_fingerprint>" ||
                    records[1].client == "<fingerprint>");
        },
        Err(err) => { println!("Unexpected error: {}", err); assert!(false); }
    }

    // Fake travelling in the future, and evict both records.
    db.flush().unwrap();
}
