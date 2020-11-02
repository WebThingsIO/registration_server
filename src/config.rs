// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::database::DatabasePool;

#[derive(Clone, Deserialize)]
#[allow(non_snake_case)]
pub struct Continent {
    pub AF: Option<String>,
    pub AN: Option<String>,
    pub AS: Option<String>,
    pub EU: Option<String>,
    pub NA: Option<String>,
    pub OC: Option<String>,
    pub SA: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct GeoIp {
    pub default: String,
    pub database: Option<String>,
    pub continent: Continent,
}

#[derive(Clone, Deserialize)]
pub struct GeneralOptions {
    pub host: String,
    pub http_port: u16,
    pub db_path: String,
    pub domain: String,
}

#[derive(Clone, Deserialize)]
pub struct PdnsOptions {
    pub socket_path: Option<String>,
    pub dns_ttl: u32,
    pub tunnel_ttl: u32,
    pub api_ttl: u32,
    pub caa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub ns_records: Vec<Vec<String>>,
    pub txt_records: Vec<Vec<String>>,
    pub soa_record: String,
    pub www_addresses: Vec<String>,
    pub geoip: GeoIp,
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
    pub db: DatabasePool,
    pub options: Args,
}

impl Config {
    pub fn from_args(args: Args) -> Self {
        Config {
            db: DatabasePool::new(&args.general.db_path.clone()),
            options: args,
        }
    }

    #[cfg(test)]
    pub fn from_args_with_db(args: Args, db: DatabasePool) -> Self {
        Config {
            db: db,
            options: args,
        }
    }
}
