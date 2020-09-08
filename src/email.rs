// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Email related routes.

use crate::config::Config;
use lettre::smtp::authentication::{Credentials, Mechanism};
use lettre::smtp::extension::ClientId;
use lettre::smtp::{ConnectionReuseParameters, SmtpClient, SmtpTransport};
#[cfg(test)]
use lettre::stub::StubTransport;
use lettre::Transport;
use lettre_email::EmailBuilder;
use log::error;

#[allow(dead_code)]
pub struct EmailSender {
    connection: SmtpTransport,
    from: String,
}

impl EmailSender {
    pub fn new(config: &Config) -> Result<EmailSender, ()> {
        let options = &config.options;

        if options.email.server.is_none()
            || options.email.user.is_none()
            || options.email.password.is_none()
            || options.email.sender.is_none()
        {
            error!("new(): All email fields need to be set.");
            return Err(());
        }

        let builder = match SmtpClient::new_simple(&options.clone().email.server.unwrap()) {
            Ok(builder) => builder,
            Err(error) => {
                error!("new(): Error building transport: {:?}", error);
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
            .transport();

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
                error!("send(): Error building email: {:?}", error);
                return Err(());
            }
        };

        #[cfg(not(test))]
        match self.connection.send(email.clone().into()) {
            Ok(_) => Ok(()),
            Err(error) => {
                error!("send(): Error sending email: {:?}", error);
                Err(())
            }
        }

        #[cfg(test)]
        {
            let mut transport = StubTransport::new_positive();
            match transport.send(email.clone().into()) {
                Ok(_) => Ok(()),
                Err(error) => {
                    error!("send(): Error sending email: {:?}", error);
                    Err(())
                }
            }
        }
    }
}
