// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Manages the SQL database that holds the list of registered domain names.
// Each record is made of the name, the private token, and the Let's Encrypt
// challenge value.

use crate::models::{Account, Domain, NewAccount, NewDomain};
use crate::schema::accounts::dsl::*;
use crate::schema::domains::dsl::*;
use crate::schema::{accounts, domains};
use diesel;
#[cfg(feature = "mysql")]
use diesel::mysql::MysqlConnection;
#[cfg(feature = "postgres")]
use diesel::pg::PgConnection;
use diesel::prelude::*;
#[cfg(feature = "sqlite")]
use diesel::sqlite::SqliteConnection;
use log::debug;
use r2d2;
use r2d2_diesel::ConnectionManager;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "mysql")]
#[derive(Clone)]
pub struct DatabasePool(r2d2::Pool<ConnectionManager<MysqlConnection>>);

#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct DatabasePool(r2d2::Pool<ConnectionManager<PgConnection>>);

#[cfg(feature = "sqlite")]
#[derive(Clone)]
pub struct DatabasePool(r2d2::Pool<ConnectionManager<SqliteConnection>>);

impl DatabasePool {
    pub fn new(db_path: &str) -> Self {
        debug!("new(): Opening database at {}", db_path);

        #[cfg(feature = "mysql")]
        let manager = ConnectionManager::<MysqlConnection>::new(db_path);
        #[cfg(feature = "postgres")]
        let manager = ConnectionManager::<PgConnection>::new(db_path);
        #[cfg(feature = "sqlite")]
        let manager = ConnectionManager::<SqliteConnection>::new(db_path);

        let pool =
            r2d2::Pool::new(manager).expect(&format!("Unable to open database at {}", db_path));

        // Create an initial connection to enable foreign key support
        if cfg!(feature = "sqlite") {
            let db = Database(pool.get().unwrap());
            diesel::sql_query("PRAGMA foreign_keys = ON")
                .execute(db.conn())
                .expect("Failed to enable foreign key support.");
        }

        DatabasePool(pool)
    }

    pub fn get_connection(&self) -> Result<Database, &'static str> {
        match self.0.get() {
            Ok(conn) => Ok(Database(conn)),
            Err(_) => Err("Failed to get database connection."),
        }
    }
}

#[cfg(feature = "mysql")]
pub struct Database(r2d2::PooledConnection<ConnectionManager<MysqlConnection>>);

#[cfg(feature = "postgres")]
pub struct Database(r2d2::PooledConnection<ConnectionManager<PgConnection>>);

#[cfg(feature = "sqlite")]
pub struct Database(r2d2::PooledConnection<ConnectionManager<SqliteConnection>>);

impl Database {
    #[cfg(feature = "mysql")]
    pub fn conn(&self) -> &MysqlConnection {
        &*self.0
    }

    #[cfg(feature = "postgres")]
    pub fn conn(&self) -> &PgConnection {
        &*self.0
    }

    #[cfg(feature = "sqlite")]
    pub fn conn(&self) -> &SqliteConnection {
        &*self.0
    }

    pub fn add_account<'a>(&self, _email: &'a str, _optout: bool) -> QueryResult<Account> {
        let new_account = NewAccount {
            email: _email,
            optout: _optout,
        };

        match diesel::insert_into(accounts::table)
            .values(&new_account)
            .execute(self.conn())
        {
            Ok(_) => self.get_account_by_email(_email),
            Err(e) => Err(e),
        }
    }

    pub fn update_account_optout(&self, _email: &str, _optout: bool) -> QueryResult<usize> {
        diesel::update(accounts.filter(email.eq(_email)))
            .set(optout.eq(_optout))
            .execute(self.conn())
    }

    pub fn delete_account(&self, _email: &str) -> QueryResult<usize> {
        let mut rows: usize = 0;

        match accounts
            .filter(email.eq(_email))
            .first::<Account>(self.conn())
        {
            Ok(_account) => {
                match diesel::delete(accounts.find(_account.id)).execute(self.conn()) {
                    Ok(count) => rows += count,
                    Err(diesel::result::Error::NotFound) => (),
                    Err(e) => return Err(e),
                }

                match diesel::delete(domains.filter(account_id.eq(_account.id)))
                    .execute(self.conn())
                {
                    Ok(count) => Ok(rows + count),
                    Err(diesel::result::Error::NotFound) => Ok(rows),
                    Err(e) => Err(e),
                }
            }
            Err(diesel::result::Error::NotFound) => Ok(0),
            Err(e) => Err(e),
        }
    }

    pub fn get_unknown_account(&self) -> QueryResult<Account> {
        match accounts
            .filter(email.eq(""))
            .limit(1)
            .first::<Account>(self.conn())
        {
            Ok(a) => Ok(a),
            Err(diesel::result::Error::NotFound) => self.add_account("", true),
            Err(e) => Err(e),
        }
    }

    pub fn get_account_by_id(&self, _id: i32) -> QueryResult<Account> {
        accounts.find(_id).first::<Account>(self.conn())
    }

    pub fn get_account_by_email(&self, _email: &str) -> QueryResult<Account> {
        accounts
            .filter(email.eq(_email))
            .limit(1)
            .first::<Account>(self.conn())
    }

    pub fn get_domain_by_verification_token(&self, _token: &str) -> QueryResult<Domain> {
        domains
            .filter(verification_token.eq(_token))
            .limit(1)
            .first::<Domain>(self.conn())
    }

    pub fn get_domain_by_name(&self, _name: &str) -> QueryResult<Domain> {
        domains
            .filter(name.eq(_name))
            .limit(1)
            .first::<Domain>(self.conn())
    }

    pub fn get_domain_by_token(&self, _token: &str) -> QueryResult<Domain> {
        domains
            .filter(token.eq(_token))
            .limit(1)
            .first::<Domain>(self.conn())
    }

    pub fn get_domains_by_account_id(&self, _account_id: i32) -> QueryResult<Vec<Domain>> {
        domains
            .filter(account_id.eq(_account_id))
            .load::<Domain>(self.conn())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn add_domain<'a>(
        &self,
        _name: &'a str,
        _account_id: i32,
        _token: &'a str,
        _description: &'a str,
        _timestamp: i64,
        _dns_challenge: &'a str,
        _reclamation_token: &'a str,
        _verification_token: &'a str,
        _verified: bool,
        _continent: &'a str,
        _mode: i32,
        _ip: &'a str,
    ) -> QueryResult<Domain> {
        let new_domain = NewDomain {
            name: _name,
            account_id: _account_id,
            token: _token,
            description: _description,
            timestamp: _timestamp,
            dns_challenge: _dns_challenge,
            reclamation_token: _reclamation_token,
            verification_token: _verification_token,
            verified: _verified,
            continent: _continent,
            mode: _mode,
            last_ip: _ip,
        };

        match diesel::insert_into(domains::table)
            .values(&new_domain)
            .execute(self.conn())
        {
            Ok(_) => self.get_domain_by_name(_name),
            Err(e) => Err(e),
        }
    }

    pub fn update_domain_verification_data(
        &self,
        _token: &str,
        _account_id: Option<i32>,
        _verification_token: &str,
        _verified: bool,
    ) -> QueryResult<usize> {
        match _account_id {
            Some(_account_id) => diesel::update(domains.filter(token.eq(_token)))
                .set((
                    account_id.eq(_account_id),
                    verification_token.eq(_verification_token),
                    verified.eq(_verified),
                ))
                .execute(self.conn()),
            None => diesel::update(domains.filter(token.eq(_token)))
                .set((
                    verification_token.eq(_verification_token),
                    verified.eq(_verified),
                ))
                .execute(self.conn()),
        }
    }

    pub fn update_domain_reclamation_token(
        &self,
        _token: &str,
        _reclamation_token: &str,
    ) -> QueryResult<usize> {
        diesel::update(domains.filter(token.eq(_token)))
            .set(reclamation_token.eq(_reclamation_token))
            .execute(self.conn())
    }

    pub fn update_domain_token(
        &self,
        _name: &str,
        _token: &str,
        _continent: &str,
        _mode: i32,
        _ip: &str,
    ) -> QueryResult<usize> {
        diesel::update(domains.filter(name.eq(_name)))
            .set((
                token.eq(_token),
                continent.eq(_continent),
                mode.eq(_mode),
                last_ip.eq(_ip),
            ))
            .execute(self.conn())
    }

    pub fn update_domain_dns_challenge(
        &self,
        _token: &str,
        _dns_challenge: &str,
    ) -> QueryResult<usize> {
        diesel::update(domains.filter(token.eq(_token)))
            .set(dns_challenge.eq(_dns_challenge))
            .execute(self.conn())
    }

    pub fn update_domain_timestamp_and_ip(&self, _token: &str, _ip: &str) -> QueryResult<usize> {
        let _timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        diesel::update(domains.filter(token.eq(_token)))
            .set((timestamp.eq(_timestamp), last_ip.eq(_ip)))
            .execute(self.conn())
    }

    pub fn delete_domain_by_token(&self, _token: &str) -> QueryResult<usize> {
        diesel::delete(domains.filter(token.eq(_token))).execute(self.conn())
    }

    pub fn delete_domain_by_reclamation_token(&self, _token: &str) -> QueryResult<usize> {
        diesel::delete(domains.filter(reclamation_token.eq(_token))).execute(self.conn())
    }

    #[cfg(test)]
    pub fn flush(&self) -> QueryResult<usize> {
        let mut count: usize = 0;
        count += diesel::delete(domains).execute(self.conn()).unwrap();
        count += diesel::delete(accounts).execute(self.conn()).unwrap();

        Ok(count)
    }
}

#[test]
fn test_domain_store() {
    let _ = env_logger::try_init();

    #[cfg(feature = "mysql")]
    let db = DatabasePool::new("mysql://root:root@127.0.0.1/domain_db_test_domains");
    #[cfg(feature = "postgres")]
    let db = DatabasePool::new("postgres://postgres:password@127.0.0.1/domain_db_test_domains");
    #[cfg(feature = "sqlite")]
    let db = DatabasePool::new("domain_db_test_domains.sqlite");
    let conn = db.get_connection().expect("Getting connection.");

    // Start with an empty db.
    conn.flush().expect("Flushing the db");

    // Create a test account
    let test_account = Account {
        id: 1,
        email: "test@example.com".to_owned(),
        optout: true,
    };
    assert_eq!(
        conn.add_account(&test_account.email, test_account.optout),
        Ok(test_account.clone())
    );

    // Fail to add same account.
    let e = conn
        .add_account(&test_account.email, test_account.optout)
        .unwrap_err();
    match e {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => (),
        _ => panic!("Adding same account resulted in wrong error."),
    }

    // Check that we don't find any record.
    assert_eq!(
        conn.get_domain_by_name("test.example.org"),
        Err(diesel::result::Error::NotFound)
    );

    assert_eq!(
        conn.get_domain_by_token("test-token"),
        Err(diesel::result::Error::NotFound)
    );

    // Add a record without a DNS challenge.
    let mut no_challenge_record = Domain {
        id: 1,
        name: "test.example.org".to_owned(),
        account_id: 1,
        token: "test-token".to_owned(),
        description: "Test Server".to_owned(),
        timestamp: 0,
        dns_challenge: "".to_owned(),
        reclamation_token: "".to_owned(),
        verification_token: "verification-token".to_owned(),
        verified: false,
        continent: "EU".to_owned(),
        mode: 0,
        last_ip: "1.2.3.4".to_owned(),
    };
    assert_eq!(
        conn.add_domain(
            "test.example.org",
            1,
            "test-token",
            "Test Server",
            0,
            "",
            "",
            "verification-token",
            false,
            "EU",
            0,
            "1.2.3.4"
        ),
        Ok(no_challenge_record.clone())
    );

    // Check that we can find it and that it matches our record.
    assert_eq!(
        conn.get_domain_by_name("test.example.org"),
        Ok(no_challenge_record.clone())
    );

    assert_eq!(
        conn.get_domain_by_token("test-token"),
        Ok(no_challenge_record.clone())
    );

    assert_eq!(
        conn.get_domain_by_verification_token("verification-token"),
        Ok(no_challenge_record.clone())
    );

    // Update the record to have challenge.
    let challenge_record = Domain {
        id: 1,
        name: "test.example.org".to_owned(),
        account_id: 1,
        token: "test-token".to_owned(),
        description: "Test Server".to_owned(),
        timestamp: 0,
        dns_challenge: "dns-challenge".to_owned(),
        reclamation_token: "".to_owned(),
        verification_token: "verification-token".to_owned(),
        verified: false,
        continent: "EU".to_owned(),
        mode: 0,
        last_ip: "1.2.3.4".to_owned(),
    };
    assert_eq!(
        conn.update_domain_dns_challenge("test-token", "dns-challenge"),
        Ok(1)
    );

    // Check that we can find it and that it matches our record.
    assert_eq!(
        conn.get_domain_by_name("test.example.org"),
        Ok(challenge_record.clone())
    );

    assert_eq!(
        conn.get_domain_by_token("test-token"),
        Ok(challenge_record.clone())
    );

    // Remove by token.
    assert_eq!(conn.delete_domain_by_token(&challenge_record.token), Ok(1));

    assert_eq!(
        conn.get_domain_by_name(&challenge_record.name),
        Err(diesel::result::Error::NotFound)
    );

    // Add a record without a reclamation token.
    no_challenge_record.id = 2;
    no_challenge_record.verification_token = "".to_owned();
    assert_eq!(
        conn.add_domain(
            "test.example.org",
            1,
            "test-token",
            "Test Server",
            0,
            "",
            "",
            "",
            false,
            "EU",
            0,
            "1.2.3.4"
        ),
        Ok(no_challenge_record.clone())
    );

    // Update the record by name to have a reclamation token.
    assert_eq!(
        conn.update_domain_reclamation_token("test-token", "test-reclamation-token"),
        Ok(1)
    );

    // Update the record's token
    let updated_record = Domain {
        id: 2,
        name: "test.example.org".to_owned(),
        account_id: 1,
        token: "new-token".to_owned(),
        description: "Test Server".to_owned(),
        timestamp: 0,
        dns_challenge: "".to_owned(),
        reclamation_token: "test-reclamation-token".to_owned(),
        verification_token: "".to_owned(),
        verified: false,
        continent: "".to_owned(),
        mode: 1,
        last_ip: "5.6.7.8".to_owned(),
    };
    assert_eq!(
        conn.update_domain_token("test.example.org", "new-token", "", 1, "5.6.7.8"),
        Ok(1)
    );
    assert_eq!(
        conn.get_domain_by_token("new-token"),
        Ok(updated_record.clone())
    );

    // Update the timestamp
    assert_eq!(
        conn.update_domain_timestamp_and_ip(&updated_record.token, "1.1.1.1"),
        Ok(1)
    );

    // Remove by reclamation token.
    assert_eq!(
        conn.delete_domain_by_reclamation_token(&updated_record.reclamation_token),
        Ok(1)
    );

    assert_eq!(
        conn.get_domain_by_name(&updated_record.name),
        Err(diesel::result::Error::NotFound)
    );
}

#[test]
fn test_email() {
    let _ = env_logger::try_init();

    #[cfg(feature = "mysql")]
    let db = DatabasePool::new("mysql://root:root@127.0.0.1/domain_db_test_email");
    #[cfg(feature = "postgres")]
    let db = DatabasePool::new("postgres://postgres:password@127.0.0.1/domain_db_test_email");
    #[cfg(feature = "sqlite")]
    let db = DatabasePool::new("domain_db_test_email.sqlite");
    let conn = db.get_connection().expect("Getting connection.");

    // Start with an empty db.
    conn.flush().expect("Flushing the db");

    let test_account = Account {
        id: 1,
        email: "test@example.com".to_owned(),
        optout: true,
    };

    assert_eq!(
        conn.get_account_by_email(&test_account.email),
        Err(diesel::result::Error::NotFound)
    );
    assert_eq!(
        conn.add_account(&test_account.email, test_account.optout),
        Ok(test_account.clone())
    );
    assert_eq!(
        conn.get_account_by_email(&test_account.email),
        Ok(test_account.clone())
    );
    assert_eq!(conn.delete_account(&test_account.email), Ok(1));
    assert_eq!(conn.delete_account(&test_account.email), Ok(0));
    assert_eq!(
        conn.get_account_by_email(&test_account.email),
        Err(diesel::result::Error::NotFound)
    );

    // Create a domain linked to an account, and verify that deleting the account also deletes the
    // domain.
    let test_account_id = conn
        .add_account(&test_account.email, test_account.optout)
        .unwrap()
        .id;
    assert!(conn
        .add_domain(
            "test.example.org",
            test_account_id,
            "test-token",
            "Test Server",
            0,
            "",
            "",
            "",
            false,
            "",
            0,
            "1.2.3.4"
        )
        .is_ok());
    assert!(
        conn.get_domains_by_account_id(test_account_id)
            .unwrap()
            .len()
            == 1
    );
    assert!(conn.delete_account(&test_account.email).is_ok());
    assert!(
        conn.get_domains_by_account_id(test_account_id)
            .unwrap()
            .len()
            == 0
    );

    assert_eq!(
        conn.get_unknown_account().unwrap(),
        Account {
            id: 3,
            email: "".to_owned(),
            optout: true,
        }
    );
}
