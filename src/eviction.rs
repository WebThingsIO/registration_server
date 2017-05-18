// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use config::Config;
use database::SqlParam;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// We evict the local_ip info from records older than EVICTION_DELAY.
// Clients should renew their registration at a shorter interval.

pub fn evict_old_entries(config: &Config) {
    let delay = config.options.general.eviction_delay;
    let db = config.db.clone();
    thread::Builder::new()
        .name("eviction".into())
        .spawn(move || {
            info!("Starting eviction thread, delay is {}s", delay);
            loop {
                thread::sleep(Duration::new(delay as u64, 0));
                let max_age = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap() -
                               Duration::new(delay as u64, 0))
                        .as_secs();
                info!("Checking for records older than {}", max_age);
                // Eviction a record means resetting the IP fields to be empty.
                match db.evict_records(SqlParam::Integer(max_age as i64))
                          .recv()
                          .unwrap() {
                    Err(err) => error!("Error evicting old records: {:?}", err),
                    Ok(count) => info!("Evicted {} records.", count),
                }
            }
        })
        .expect("Failed to start eviction thread!");
}

#[cfg(test)]
mod tests {
    use super::*;
    use args::ArgsParser;
    use config::Config;
    use database::{Database, DomainRecord};
    use std::time::Duration;

    #[test]
    fn eviction_thread() {
        let args = ArgsParser::from_vec(vec!["registration_server",
                                             "--config-file=./config.toml.test"]);

        let db = Database::new("domain_db_test_eviction.sqlite");
        db.flush().recv().unwrap().expect("Flushing the db");

        let mut arg_config = Config::from_args(args);
        let config = arg_config.with_db(db.clone());

        // Add a entry to the database, with a current timestamp.
        let max_age = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let eviction_record = DomainRecord::new("test-token-eviction",
                                                "local.eviction.example.org",
                                                "eviction.example.org",
                                                None,
                                                Some("local_ip"),
                                                Some("public_ip"),
                                                "Test Server",
                                                Some("eviction@example.com"),
                                                max_age);
        assert_eq!(db.add_record(eviction_record.clone()).recv().unwrap(),
                   Ok(()));

        // Check that the record has not been evicted yet.
        assert_eq!(db.get_record_by_token("test-token-eviction")
                       .recv()
                       .unwrap(),
                   Ok(eviction_record));


        // Start the eviction thread and wait forthe eviction to happen.
        evict_old_entries(&config);

        thread::sleep(Duration::new(6, 0));

        let evicted = db.get_record_by_token("test-token-eviction")
            .recv()
            .unwrap()
            .unwrap();
        assert_eq!(evicted.email, Some("eviction@example.com".to_owned()));
        assert_eq!(evicted.local_ip, None);
        assert_eq!(evicted.public_ip, None);
        assert!(evicted.timestamp > max_age);
    }
}
