// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Email related routes.

use config::Config;
use database::DatabaseError;
use email::Mailbox;
use errors::*;
use iron::headers::ContentType;
use lettre_email::EmailBuilder;
use lettre::{EmailTransport, SmtpTransport};
use lettre::smtp::ConnectionReuseParameters;
use lettre::smtp::authentication::{Credentials, Mechanism};
use lettre::smtp::extension::ClientId;
#[cfg(test)]
use lettre::stub::StubEmailTransport;
use iron::prelude::*;
use iron::status::{self, Status};
use params::{FromValue, Params};
use std::str::FromStr;
use uuid::Uuid;

#[allow(dead_code)]
pub struct EmailSender {
    connection: SmtpTransport,
    from: String,
}

impl EmailSender {
    pub fn new(config: &Config) -> Result<EmailSender, ()> {
        let options = &config.options;

        if options.email.server.is_none() || options.email.user.is_none()
            || options.email.password.is_none() || options.email.sender.is_none()
        {
            error!("All email fields need to be set.");
            return Err(());
        }

        let builder = match SmtpTransport::simple_builder(options.clone().email.server.unwrap()) {
            Ok(builder) => builder,
            Err(error) => {
                error!("{:?}", error);
                return Err(());
            }
        };

        let user = options.clone().email.user.unwrap().clone();
        let password = options.clone().email.password.unwrap().clone();
        let connection = builder
            .hello_name(ClientId::Domain("localhost".to_owned()))
            .credentials(Credentials::new(user, password))
            .smtp_utf8(true)
            .authentication_mechanism(Mechanism::Plain)
            .connection_reuse(ConnectionReuseParameters::ReuseUnlimited)
            .build();

        Ok(EmailSender {
            connection: connection,
            from: options.clone().email.sender.unwrap().clone(),
        })
    }

    pub fn send(&mut self, to: &str, body: &str, subject: &str) -> Result<(), ()> {
        let email = match EmailBuilder::new()
            .to(to)
            .from(&*self.from)
            .html(body)
            .subject(subject)
            .build()
        {
            Ok(email) => email,
            Err(error) => {
                error!("{:?}", error);
                return Err(());
            }
        };

        #[cfg(not(test))]
        match self.connection.send(&email.clone()) {
            Ok(_) => Ok(()),
            Err(error) => {
                error!("{:?}", error);
                Err(())
            }
        }

        #[cfg(test)]
        {
            let mut transport = StubEmailTransport::new_positive();
            match transport.send(&email.clone()) {
                Ok(_) => Ok(()),
                Err(error) => {
                    error!("{:?}", error);
                    Err(())
                }
            }
        }
    }
}

pub fn setemail(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /setemail");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    let email = map.find(&["email"]);

    if token.is_none() || email.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();
    let email = String::from_value(email.unwrap()).unwrap();
    // Check that this is a valid email address.
    if Mailbox::from_str(&email).is_err() {
        return EndpointError::with(status::BadRequest, 400);
    }

    // Check that this is a valid token.
    let record = config.db.get_record_by_token(&token).recv().unwrap();
    if record.is_err() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let mut record = record.unwrap();

    let account_id = match config.db.get_account_id_by_email(&email).recv().unwrap() {
        Ok(id) => id,
        Err(_) => match config.db.add_email(&email).recv().unwrap() {
            Ok(id) => id,
            Err(_) => {
                return EndpointError::with(status::InternalServerError, 501);
            }
        },
    };

    // Update the record.
    let verification_token = format!("{}", Uuid::new_v4());
    record.account_id = account_id;
    record.verification_token = verification_token.clone();
    record.verified = false;

    match config.db.update_record(record).recv().unwrap() {
        Ok(_) => match EmailSender::new(config) {
            Ok(mut sender) => {
                let scheme = match config.options.general.identity_directory {
                    Some(_) => "https",
                    None => "http",
                };
                let full_link = format!(
                    "{}://api.{}/verifyemail?s={}",
                    scheme,
                    config.options.general.domain,
                    verification_token
                );
                let body = config
                    .options
                    .email
                    .clone()
                    .confirmation_body
                    .unwrap()
                    .replace("{link}", &full_link);
                match sender.send(
                    &email,
                    &body,
                    &config.options.email.clone().confirmation_title.unwrap(),
                ) {
                    Ok(_) => ok_response!(),
                    Err(_) => EndpointError::with(status::InternalServerError, 501),
                }
            }
            Err(_) => EndpointError::with(status::InternalServerError, 501),
        },
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

// Process email confirmation links that have the link as the "s" parameter.
pub fn verifyemail(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /verifyemail");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let link = map.find(&["s"]);

    if link.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let link = String::from_value(link.unwrap()).unwrap();

    match config
        .db
        .get_record_by_verification_token(&link)
        .recv()
        .unwrap()
    {
        Ok(mut record) => {
            // Update the record's verification state.
            record.verified = true;
            record.verification_token = "".to_owned();
            match config.db.update_record(record).recv().unwrap() {
                Ok(_) => html_response!(config.options.email.clone().success_page.unwrap()),
                Err(DatabaseError::NoRecord) => {
                    html_response!(config.options.email.clone().error_page.unwrap())
                }
                Err(_) => EndpointError::with(status::InternalServerError, 501),
            }
        }
        Err(DatabaseError::NoRecord) => {
            html_response!(config.options.email.clone().error_page.unwrap())
        }
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

pub fn revokeemail(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /revokeemail");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);

    if token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();

    // Check that this is a valid token.
    let record = config.db.get_record_by_token(&token).recv().unwrap();
    if record.is_err() {
        return EndpointError::with(status::BadRequest, 400);
    }

    // Update the record's verification state.
    let mut record = record.unwrap();
    record.verified = false;
    record.verification_token = "".to_owned();

    match config.db.update_record(record).recv().unwrap() {
        Ok(_) => ok_response!(),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}
