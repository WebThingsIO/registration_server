/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use db::Db;
use std::time::Duration;
use std::thread;

const EVICTION_DELAY: i64 = 10; // Eviction delay in minutes.

pub fn start() {
    thread::Builder::new().name("Eviction".to_owned()).spawn(move || {
        loop {
            let db = Db::new();
            let now = Db::seconds_from_epoch();
            match db.delete_older_than(now - EVICTION_DELAY * 60) {
                Ok(count) => info!("Evicted {} foxbox registrations.", count),
                Err(err) => error!("Eviction failed: {}", err)
            }
            thread::sleep(Duration::from_secs(EVICTION_DELAY as u64 * 60));
        }
    }).unwrap();
}
