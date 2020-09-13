// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::config::Config;
use crate::constants::DomainMode;
use crate::email::EmailSender;
use crate::pdns::lookup_continent;
use actix_web::{get, web, HttpRequest, HttpResponse};
use diesel;
use email::Mailbox;
use log::{error, info};
use regex::Regex;
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
struct NameAndToken {
    name: String,
    token: String,
}

#[derive(Deserialize, Serialize)]
struct SubscribeError {
    error: String,
}

#[derive(Deserialize)]
struct PingParams {
    token: String,
}

#[derive(Deserialize)]
struct InfoParams {
    token: String,
}

#[derive(Deserialize)]
struct SubscribeParams {
    name: String,
    #[serde(rename = "reclamationToken")]
    reclamation_token: Option<String>,
    email: Option<String>,
    desc: Option<String>,
    mode: Option<DomainMode>,
}

#[derive(Deserialize)]
struct ReclaimParams {
    name: String,
}

#[derive(Deserialize)]
struct UnsubscribeParams {
    token: Option<String>,
    #[serde(rename = "reclamationToken")]
    reclamation_token: Option<String>,
}

#[derive(Deserialize)]
struct DnsConfigParams {
    token: String,
    challenge: String,
}

#[derive(Deserialize)]
struct SetEmailParams {
    token: String,
    email: String,
    optout: Option<u8>,
}

#[derive(Deserialize)]
struct RevokeEmailParams {
    token: String,
}

#[derive(Deserialize)]
struct VerifyEmailParams {
    s: String,
}

/// Generate the full domain for the given subdomain name.
fn domain_for_name(name: &str, config: &Config) -> String {
    format!("{}.{}.", name, config.options.general.domain).to_lowercase()
}

/// Get the actual IP a request is coming from.
fn get_real_ip(req: &HttpRequest) -> Option<IpAddr> {
    if cfg!(test) {
        return Some("127.0.0.1".parse().unwrap());
    }

    let connection_info = req.connection_info();
    let remote: Option<IpAddr> = match connection_info.remote_addr() {
        Some(x) => {
            let parts: Vec<&str> = x.split(":").collect();
            if parts.len() == 2 {
                Some(parts[0].parse().unwrap())
            } else {
                None
            }
        }
        None => None,
    };
    match req.headers().get("X-Real-IP") {
        Some(x) => match x.to_str() {
            Ok(v) => Some(v.parse().unwrap()),
            Err(_) => remote,
        },
        None => remote,
    }
}

#[get("/connectivity-check")]
async fn connectivity_check(_req: HttpRequest) -> &'static str {
    "OK"
}

#[get("/ping")]
async fn ping(
    req: HttpRequest,
    params: web::Query<PingParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "ping(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    let real_ip = get_real_ip(&req);
    if real_ip.is_none() {
        return HttpResponse::BadRequest().finish();
    }
    let real_ip = real_ip.unwrap();

    info!("GET {:?}", req.uri());

    // Save this ping in the database if we know about this token.
    match conn.update_domain_timestamp_and_ip(&params.token, &real_ip.to_string()) {
        Ok(count) if count > 0 => HttpResponse::Ok().finish(),
        Ok(_) => HttpResponse::NotFound().finish(),
        Err(err) => {
            error!("ping(): Failed to update domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/info")]
async fn info(
    req: HttpRequest,
    params: web::Query<InfoParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "info(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());

    match conn.get_domain_by_token(&params.token) {
        Ok(record) => HttpResponse::Ok().json(&record),
        Err(diesel::result::Error::NotFound) => HttpResponse::NotFound().finish(),
        Err(err) => {
            error!("info(): Failed to get domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/subscribe")]
async fn subscribe(
    req: HttpRequest,
    params: web::Query<SubscribeParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "subscribe(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    let real_ip = get_real_ip(&req);
    if real_ip.is_none() {
        return HttpResponse::BadRequest().finish();
    }
    let real_ip = real_ip.unwrap();

    let continent = if config.options.pdns.geoip.database.is_some() {
        match lookup_continent(real_ip, &config) {
            Some(val) => val,
            None => "".to_owned(),
        }
    } else {
        "".to_owned()
    };

    info!("GET {:?}", req.uri());

    let subdomain = params.name.trim().to_lowercase();
    let full_name = domain_for_name(&subdomain, &config);

    let domain_mode = match params.mode {
        Some(m) => m,
        None => DomainMode::Tunneled,
    };

    // Ensure that subdomain is valid:
    // - Contains only a-z, 0-9, and hyphens, but does not start or end with hyphen.
    // - Is not equal to "api", "www", or "_psl" as those are reserved.
    let re = Regex::new(r"^([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$").unwrap();
    let ns_regex = Regex::new(r"^ns\d*$").unwrap();
    if !re.is_match(&subdomain)
        || ns_regex.is_match(&subdomain)
        || subdomain == "api"
        || subdomain == "www"
        || subdomain == "_psl"
        || subdomain.len() > 63
        || full_name.len() > 253
    {
        return HttpResponse::BadRequest().json(SubscribeError {
            error: "UnavailableName".to_owned(),
        });
    }

    info!("subscribe(): Trying to subscribe: {}", full_name);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match conn.get_domain_by_name(&full_name) {
        Ok(record) => {
            if params.reclamation_token.is_some() {
                let reclamation_token = params.reclamation_token.clone().unwrap();
                if reclamation_token == record.reclamation_token {
                    // Create a new token and update the existing record.
                    let token = format!("{}", Uuid::new_v4());
                    match conn.update_domain_token(
                        &record.name,
                        &token,
                        &continent,
                        domain_mode as i32,
                        &real_ip.to_string(),
                    ) {
                        Ok(count) if count > 0 => {
                            // We don't want the full domain name or the DNS challenge in the
                            // response, so we create a local struct.
                            HttpResponse::Ok().json(NameAndToken {
                                name: subdomain.to_owned(),
                                token: token,
                            })
                        }
                        Ok(_) => HttpResponse::NotFound().finish(),
                        Err(err) => {
                            error!("subscribe(): Failed to update domain: {:?}", err);
                            HttpResponse::InternalServerError().finish()
                        }
                    }
                } else {
                    HttpResponse::BadRequest().json(SubscribeError {
                        error: "ReclamationTokenMismatch".to_owned(),
                    })
                }
            } else {
                // We already have a record for this name, return an error.
                if params.email.is_some() {
                    let email = params.email.clone().unwrap();
                    if !email.is_empty() {
                        match conn.get_account_by_id(record.account_id) {
                            Ok(account) => {
                                if email == account.email {
                                    return HttpResponse::BadRequest().json(SubscribeError {
                                        error: "UnavailableNameReclamationPossible".to_owned(),
                                    });
                                }
                            }
                            Err(_) => {
                                return HttpResponse::BadRequest().json(SubscribeError {
                                    error: "UnavailableName".to_owned(),
                                });
                            }
                        }
                    }
                }

                HttpResponse::BadRequest().json(SubscribeError {
                    error: "UnavailableName".to_owned(),
                })
            }
        }
        Err(diesel::result::Error::NotFound) => {
            // Create a token, create and store a record, and finally, return the token.
            let token = format!("{}", Uuid::new_v4());

            let description = match params.desc {
                Some(ref desc) => desc.clone(),
                _ => format!("{}'s server", params.name),
            };

            let result = conn.get_unknown_account();
            if result.is_err() {
                error!(
                    "subscribe(): Failed to get the unknown account: {:?}",
                    result.err()
                );
                return HttpResponse::InternalServerError().finish();
            }

            let account = result.unwrap();
            match conn.add_domain(
                &full_name,
                account.id,
                &token,
                &description,
                timestamp,
                "",
                "",
                "",
                false,
                &continent,
                domain_mode as i32,
                &real_ip.to_string(),
            ) {
                Ok(_) => {
                    // We don't want the full domain name or the DNS challenge in the response, so
                    // we create a local struct.
                    HttpResponse::Ok().json(NameAndToken {
                        name: subdomain.to_owned(),
                        token: token,
                    })
                }
                Err(err) => {
                    error!("subscribe(): Failed to add domain: {:?}", err);
                    HttpResponse::InternalServerError().finish()
                }
            }
        }
        // Other error, like a db issue.
        Err(err) => {
            error!("subscribe(): Failed to look up domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/reclaim")]
async fn reclaim(
    req: HttpRequest,
    params: web::Query<ReclaimParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "reclaim(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());

    let subdomain = params.name.trim().to_lowercase();
    let full_name = domain_for_name(&subdomain, &config);

    match conn.get_domain_by_name(&full_name) {
        Ok(record) => {
            match conn.get_account_by_id(record.account_id) {
                Ok(account) => {
                    if account.email == "" {
                        return HttpResponse::BadRequest().json(SubscribeError {
                            error: "NoEmail".to_owned(),
                        });
                    }

                    let token = format!("{}", Uuid::new_v4());
                    let result = conn.update_domain_reclamation_token(&record.token, &token);
                    if result.is_err() {
                        error!("reclaim(): Failed to update domain: {:?}", result.err());
                        return HttpResponse::InternalServerError().finish();
                    }

                    if result.unwrap() == 0 {
                        return HttpResponse::NotFound().finish();
                    }

                    // Send the reclamation token to the user via email.
                    match EmailSender::new(&config) {
                        Ok(mut sender) => {
                            let body = config
                                .options
                                .email
                                .clone()
                                .reclamation_body
                                .unwrap()
                                .replace("{token}", &token);
                            match sender.send(
                                &account.email,
                                &body,
                                &config.options.email.clone().reclamation_title.unwrap(),
                            ) {
                                Ok(_) => HttpResponse::Ok().finish(),
                                Err(err) => {
                                    error!("reclaim(): Failed to send email: {:?}", err);
                                    HttpResponse::InternalServerError().finish()
                                }
                            }
                        }
                        Err(err) => {
                            error!("reclaim(): Failed to create email sender: {:?}", err);
                            HttpResponse::InternalServerError().finish()
                        }
                    }
                }
                Err(_) => {
                    // This name doesn't have an associated email address.
                    HttpResponse::BadRequest().json(SubscribeError {
                        error: "NoEmail".to_owned(),
                    })
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            // This name doesn't exist, no need to reclaim it.
            HttpResponse::BadRequest().json(SubscribeError {
                error: "NoSuchName".to_owned(),
            })
        }
        // Other error, like a db issue.
        Err(err) => {
            error!("reclaim(): Failed to look up domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/unsubscribe")]
async fn unsubscribe(
    req: HttpRequest,
    params: web::Query<UnsubscribeParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "unsubscribe(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());

    if params.token.is_none() {
        match &params.reclamation_token {
            Some(reclamation_token) => {
                return match conn.delete_domain_by_reclamation_token(&reclamation_token) {
                    Ok(0) => {
                        // No record found for this token.
                        HttpResponse::NotFound().finish()
                    }
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(err) => {
                        error!("unsubscribe(): Failed to delete domain: {:?}", err);
                        HttpResponse::InternalServerError().finish()
                    }
                };
            }
            _ => {
                // No token or reclamation token provided.
                return HttpResponse::BadRequest().finish();
            }
        }
    }

    match conn.delete_domain_by_token(&params.token.as_ref().unwrap()) {
        Ok(0) => HttpResponse::BadRequest().finish(), // No record found for this token.
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => {
            error!("unsubscribe(): Failed to delete domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/dnsconfig")]
async fn dns_config(
    req: HttpRequest,
    params: web::Query<DnsConfigParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "dns_config(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());

    if params.challenge.len() > 63 {
        error!("dns_config(): Invalid challenge: {}", params.challenge);
        return HttpResponse::BadRequest().finish();
    }

    match conn.update_domain_dns_challenge(&params.token, &params.challenge) {
        Ok(count) if count > 0 => HttpResponse::Ok().finish(),
        Ok(_) => HttpResponse::NotFound().finish(),
        Err(err) => {
            error!("dns_config(): Failed to update domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/setemail")]
async fn set_email(
    req: HttpRequest,
    params: web::Query<SetEmailParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "set_email(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());

    let optout = match params.optout {
        Some(val) => {
            if val == 1 {
                true
            } else {
                false
            }
        }
        None => false,
    };

    // Check that this is a valid email address.
    if Mailbox::from_str(&params.email).is_err() || params.email.len() > 254 {
        error!("set_email(): Invalid email address: {}", params.email);
        return HttpResponse::BadRequest().finish();
    }

    let account_id = match conn.get_account_by_email(&params.email) {
        Ok(account) => match conn.update_account_optout(&params.email, optout) {
            Ok(_) => account.id,
            Err(err) => {
                error!(
                    "set_email(): Failed to update account opt-out status: {:?}",
                    err
                );
                return HttpResponse::InternalServerError().finish();
            }
        },
        Err(_) => match conn.add_account(&params.email, optout) {
            Ok(account) => account.id,
            Err(err) => {
                error!("set_email(): Failed to add account: {:?}", err);
                return HttpResponse::InternalServerError().finish();
            }
        },
    };

    let domain = conn.get_domain_by_token(&params.token);
    if domain.is_err() {
        error!(
            "set_email(): Failed to find domain for token {}: {:?}",
            params.token,
            domain.unwrap_err()
        );
        return HttpResponse::NotFound().finish();
    }
    let domain = domain.unwrap();
    let domain = domain.name.trim_end_matches('.');

    let verification_token = format!("{}", Uuid::new_v4());
    match conn.update_domain_verification_data(
        &params.token,
        Some(account_id),
        &verification_token,
        false,
    ) {
        Ok(count) if count > 0 => match EmailSender::new(&config) {
            Ok(mut sender) => {
                let full_link = format!(
                    "http://api.{}/verifyemail?s={}",
                    config.options.general.domain, verification_token
                );
                let body = config
                    .options
                    .email
                    .clone()
                    .confirmation_body
                    .unwrap()
                    .replace("{link}", &full_link)
                    .replace("{domain}", &domain);
                match sender.send(
                    &params.email,
                    &body,
                    &config.options.email.clone().confirmation_title.unwrap(),
                ) {
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(err) => {
                        error!("set_email(): Failed to send email: {:?}", err);
                        HttpResponse::InternalServerError().finish()
                    }
                }
            }
            Err(err) => {
                error!("set_email(): Failed to create email sender: {:?}", err);
                HttpResponse::InternalServerError().finish()
            }
        },
        Ok(_) => {
            error!("set_email(): Domain not found for token: {}", params.token);
            HttpResponse::NotFound().finish()
        }
        Err(err) => {
            error!("set_email(): Failed to update domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/revokeemail")]
async fn revoke_email(
    req: HttpRequest,
    params: web::Query<RevokeEmailParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "revoke_email(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());
    match conn.update_domain_verification_data(&params.token, None, "", false) {
        Ok(count) if count > 0 => HttpResponse::Ok().finish(),
        Ok(_) => HttpResponse::NotFound().finish(),
        Err(err) => {
            error!("revoke_email(): Failed to update domain: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

// Process email confirmation links that have the link as the "s" parameter.
#[get("/verifyemail")]
async fn verify_email(
    req: HttpRequest,
    params: web::Query<VerifyEmailParams>,
    config: web::Data<Config>,
) -> HttpResponse {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "verify_email(): Failed to get database connection: {:?}",
            conn.err()
        );
        return HttpResponse::InternalServerError().finish();
    }
    let conn = conn.unwrap();

    info!("GET {:?}", req.uri());

    match conn.get_domain_by_verification_token(&params.s) {
        Ok(record) => match conn.update_domain_verification_data(
            &record.token,
            Some(record.account_id),
            "",
            true,
        ) {
            Ok(count) if count > 0 => HttpResponse::Ok()
                .content_type("text/html")
                .body(config.options.email.clone().success_page.unwrap()),
            Ok(_) => HttpResponse::NotFound()
                .content_type("text/html")
                .body(config.options.email.clone().error_page.unwrap()),
            Err(err) => {
                error!("verify_email(): Failed to update domain: {:?}", err);
                HttpResponse::InternalServerError().finish()
            }
        },
        Err(diesel::result::Error::NotFound) => HttpResponse::NotFound()
            .content_type("text/html")
            .body(config.options.email.clone().error_page.unwrap()),
        Err(err) => {
            error!(
                "verifyemail(): Failed to lookup domain for {}: {:?}",
                params.s, err
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::ArgsParser;
    use crate::config::Config;
    use crate::database::DatabasePool;
    use crate::models::Domain;
    use actix_rt;
    use actix_web::{middleware, test, App};
    use bytes::Bytes;
    use std;
    use std::thread::sleep;
    use std::time;

    #[actix_rt::test]
    async fn test_routes() {
        let _ = env_logger::try_init();

        #[cfg(feature = "mysql")]
        let db = DatabasePool::new("mysql://root:root@127.0.0.1/domain_db_test_routes");
        #[cfg(feature = "postgres")]
        let db = DatabasePool::new("postgres://postgres:password@127.0.0.1/domain_db_test_routes");
        #[cfg(feature = "sqlite")]
        let db = DatabasePool::new("domain_db_test_routes.sqlite");
        let conn = db.get_connection().expect("Getting connection.");
        conn.flush().expect("Flushing the db");

        let args = ArgsParser::from_vec(vec![
            "registration_server",
            "--config-file=./config/config.toml",
        ]);
        let config = Config::from_args_with_db(args.clone(), db.clone());

        let mut app = test::init_service(
            App::new()
                .data(config)
                .wrap(
                    middleware::DefaultHeaders::new()
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Methods", "GET, OPTIONS"),
                )
                .service(connectivity_check)
                .service(ping)
                .service(info)
                .service(subscribe)
                .service(reclaim)
                .service(unsubscribe)
                .service(dns_config)
                .service(set_email)
                .service(revoke_email)
                .service(verify_email),
        )
        .await;

        // Connectivity check
        let resp = test::TestRequest::get()
            .uri("/connectivity-check")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body = test::read_body(resp).await;
        assert_eq!(body, Bytes::from_static(b"OK"));

        // Subscribe a test user.
        let resp = test::TestRequest::get()
            .uri("/subscribe")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=-test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=test-")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=ns")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=ns123")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=api")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=www")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri(
                "/subscribe?name=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\
            abcdefghijklmnopqrstuvwxyz",
            )
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body: NameAndToken = test::read_body_json(resp).await;
        let token = body.token;
        assert_eq!(body.name, "test");

        // Unsubscribe
        let resp = test::TestRequest::get()
            .uri("/unsubscribe")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/unsubscribe?token=wrong_token")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri(&format!("/unsubscribe?token={}", token))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);

        // Subscribe again
        let resp = test::TestRequest::get()
            .uri("/subscribe?name=test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body: NameAndToken = test::read_body_json(resp).await;
        let token = body.token;
        assert_eq!(body.name, "test");

        // Fail to register the same name twice.
        let resp = test::TestRequest::get()
            .uri("/subscribe?name=test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        // Test reclaiming domain
        let email = "test@example.com".to_owned();
        let resp = test::TestRequest::get()
            .uri("/subscribe?name=test&email=")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri(&format!("/subscribe?name=test&email={}", email))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableName");

        let resp = test::TestRequest::get()
            .uri("/reclaim")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/reclaim?name=nonexistent")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "NoSuchName");

        let resp = test::TestRequest::get()
            .uri("/reclaim?name=test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "NoEmail");

        // Ping without the expected parameters.
        let resp = test::TestRequest::get()
            .uri("/ping")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/ping?name=test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/ping?token=wrong_token")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 404);

        // Ping properly.
        sleep(time::Duration::from_secs(1));
        let resp = test::TestRequest::get()
            .uri(&format!("/ping?token={}", token))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);

        // Get the full info
        let resp = test::TestRequest::get()
            .uri("/info")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/info?token=wrong_token")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 404);

        let resp = test::TestRequest::get()
            .uri(&format!("/info?token={}", token))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body: Domain = test::read_body_json(resp).await;
        assert_eq!(body.token, token);
        assert_eq!(body.name, "test.mydomain.org.");
        assert_eq!(body.description, r#"test's server"#);

        // Test the LE challenge endpoints.
        let resp = test::TestRequest::get()
            .uri("/dnsconfig")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/dnsconfig?token=wrong_token")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri(&format!("/dnsconfig?token={}", token))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/dnsconfig?token=wrong_token&challenge=test_challenge")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 404);

        let resp = test::TestRequest::get()
            .uri(&format!(
                "/dnsconfig?token={}&challenge=abcdefghijklmnopqrstuvwxyz\
            abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
                token
            ))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri(&format!(
                "/dnsconfig?token={}&challenge=test_challenge",
                token
            ))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);

        // Email routes tests
        // 1. set an email address
        let resp = test::TestRequest::get()
            .uri("/setemail")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/setemail?token=wrong_token")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/setemail?token=wrong_token&email=me@example.com")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 404);

        let resp = test::TestRequest::get()
            .uri(&format!("/setemail?token={}&email=not_an_email", token))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri(&format!(
                "/setemail?token={}&email=abc@{}.com",
                token,
                std::iter::repeat("makeasuperlongfakedomain.")
                    .take(10)
                    .collect::<String>()
            ))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri(&format!(
                "/setemail?token={}&email={}&optout=1",
                token, email
            ))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let record = conn.get_domain_by_token(&token).unwrap();
        let account = conn.get_account_by_id(record.account_id).unwrap();
        assert_eq!(account.email, email);
        assert_eq!(account.optout, true);

        let resp = test::TestRequest::get()
            .uri(&format!("/setemail?token={}&email={}", token, email))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let record = conn.get_domain_by_token(&token).unwrap();
        let account = conn.get_account_by_id(record.account_id).unwrap();
        assert_eq!(account.email, email);
        assert_eq!(account.optout, false);
        assert!(!record.verified);
        let link = record.verification_token;

        // 2. verify the email
        let resp = test::TestRequest::get()
            .uri("/verifyemail")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/verifyemail?s=wrong_link")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 404);
        let body = test::read_body(resp).await;
        assert_eq!(body, args.email.error_page.unwrap().into_bytes());

        let resp = test::TestRequest::get()
            .uri(&format!("/verifyemail?s={}", link))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body = test::read_body(resp).await;
        assert_eq!(body, args.email.success_page.unwrap().into_bytes());

        // 3. check that the email has been set on the domain record.
        let domain_record = conn.get_domain_by_token(&token).unwrap();
        assert!(domain_record.verified);

        // 3a. Before revoking, finish testing domain reclamation.
        let resp = test::TestRequest::get()
            .uri(&format!("/subscribe?name=test&email={}", email))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "UnavailableNameReclamationPossible");

        let resp = test::TestRequest::get()
            .uri("/reclaim?name=test")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let domain_record = conn.get_domain_by_token(&token).unwrap();

        let resp = test::TestRequest::get()
            .uri("/subscribe?name=test&reclamationToken=wrongtoken")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body: SubscribeError = test::read_body_json(resp).await;
        assert_eq!(body.error, "ReclamationTokenMismatch");

        let resp = test::TestRequest::get()
            .uri(&format!(
                "/subscribe?name=test&reclamationToken={}",
                &domain_record.reclamation_token
            ))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body: NameAndToken = test::read_body_json(resp).await;
        let token = body.token;
        assert_eq!(body.name, "test");

        // 4. email revocation
        let resp = test::TestRequest::get()
            .uri("/revokeemail")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 400);

        let resp = test::TestRequest::get()
            .uri("/revokeemail?token=wrong_token")
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 404);

        let resp = test::TestRequest::get()
            .uri(&format!("/revokeemail?token={}", token))
            .send_request(&mut app)
            .await;
        assert_eq!(resp.status().as_u16(), 200);

        // 5. Verify the verification link is empty.
        let record = conn.get_domain_by_token(&token).unwrap();
        assert_eq!(record.verification_token, "");
        assert!(!record.verified);
    }
}
