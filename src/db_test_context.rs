/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::process;
use super::db::Db;

static SERVER_PORT: u16 = 38991;
static SERVER_HOST: &'static str = "127.0.0.1";

pub struct RedisServer {
    pub process: process::Child,
}

impl RedisServer {

    pub fn new() -> RedisServer {
        let mut cmd = process::Command::new("redis-server");
        cmd
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .arg("--port").arg(SERVER_PORT.to_string())
            .arg("--bind").arg(SERVER_HOST.to_string());

        let process = cmd.spawn().unwrap();
        RedisServer { process: process }
    }
}

impl Drop for RedisServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

pub struct TestContext {
    pub server: RedisServer,
    pub db: Db
}

impl TestContext {
    pub fn new() -> TestContext {
        let server = RedisServer::new();

        let db = Db::new(SERVER_HOST.to_string(),
                         SERVER_PORT,
                         None /* password */);

        db.flush().unwrap();

        TestContext {
            server: server,
            db: db,
        }
    }
}
