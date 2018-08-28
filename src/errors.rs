// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate env_logger;
use iron::prelude::*;
use iron::status;
use serde_json;
use std::error::Error;
use std::fmt::{self, Debug};

#[derive(Debug)]
struct StringError(pub String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str {
        &*self.0
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: u16,
    pub errno: u16,
    pub error: String,
}

pub struct EndpointError;

impl EndpointError {
    pub fn with(status: status::Status, errno: u16) -> IronResult<Response> {
        let error = status.canonical_reason().unwrap().to_owned();
        let body = ErrorBody {
            code: status.to_u16(),
            errno: errno,
            error: error.clone(),
        };

        Err(IronError::new(
            StringError(error),
            (status, serde_json::to_string(&body).unwrap()),
        ))
    }
}

#[test]
fn test_error() {
    let _ = env_logger::init();

    let s_error = StringError(status::BadRequest.canonical_reason().unwrap().to_owned());
    let error = format!("{} {}", s_error, s_error.description());
    assert_eq!(error, r#"StringError("Bad Request") Bad Request"#);

    let ep_error = EndpointError::with(status::InternalServerError, 500);
    let error = ep_error.unwrap_err();
    assert_eq!(error.description(), "Internal Server Error");
    assert_eq!(error.response.status.unwrap(), status::InternalServerError);
}
