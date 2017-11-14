// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use database::Database;
use std::path::PathBuf;

#[derive(Clone, Deserialize)]
pub struct GeneralOptions {
    pub host: String,
    pub http_port: u16,
    pub https_port: u16,
    pub data_directory: String,
    pub cert_directory: Option<PathBuf>,
    pub domain: String,
    pub tunnel_ip: String,
}

#[derive(Clone, Deserialize)]
pub struct PdnsOptions {
    pub soa_content: String,
    pub socket_path: Option<String>,
    pub dns_ttl: u32,
    pub mx_record: String,
    pub caa_record: String,
    pub txt_record: String,
}

#[derive(Clone, Deserialize)]
pub struct EmailOptions {
    pub server: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub sender: Option<String>,
    pub reclamation_title: Option<String>,
    pub reclamation_body: Option<String>,
    pub confirmation_title: Option<String>,
    pub confirmation_body: Option<String>,
    pub success_page: Option<String>,
    pub error_page: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct Args {
    pub general: GeneralOptions,
    pub pdns: PdnsOptions,
    pub email: EmailOptions,
}

#[derive(Clone)]
pub struct Config {
    pub db: Database,
    pub options: Args,
}

impl Config {
    pub fn from_args(args: Args) -> Self {
        Config {
            db: Database::new(&format!("{}/domains.sqlite", args.general.data_directory)),
            options: args,
        }
    }

    #[cfg(test)]
    pub fn from_args_with_db(args: Args, db: Database) -> Self {
        Config {
            db: db,
            options: args
        }
    }
}
