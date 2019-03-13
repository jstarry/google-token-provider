use failure::Error;
use futures::future::{err, ok, Future};
use jsonwebtoken::{Algorithm, Header};
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use reqwest::r#async::Client as HTTPClient;
use reqwest::r#async::Response;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Add;
use std::rc::Rc;
use std::time::UNIX_EPOCH;
use std::time::{Duration, SystemTime};

const TOKEN_URL: &'static str = "https://www.googleapis.com/oauth2/v4/token";

#[derive(Debug, Clone)]
pub struct Credentials {
    private_key: Rsa<Private>,
    client_email: String,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

#[derive(Default, Deserialize, PartialEq, Debug, Clone)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

impl Credentials {
    pub fn new(private_key: Rsa<Private>, client_email: String) -> Self {
        Credentials {
            private_key,
            client_email,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub value: String,
    pub expires: SystemTime,
}

impl AccessToken {
    pub fn expired(&self) -> bool {
        self.expires < SystemTime::now()
    }
}

pub struct Client {
    credentials: Credentials,
    scopes: String,
    http: HTTPClient,
    access_token: Rc<RefCell<Option<AccessToken>>>,
}

impl Client {
    pub fn new(credentials: Credentials, scopes: impl Iterator<Item = String>) -> Client {
        Client {
            credentials,
            scopes: scopes.collect::<Vec<String>>().join(" "),
            http: HTTPClient::new(),
            access_token: Rc::default(),
        }
    }

    pub fn get_token(&mut self) -> Box<Future<Item = AccessToken, Error = Error>> {
        if let Some(token) = self.access_token.borrow().clone() {
            if !token.expired() {
                return Box::new(ok(token.clone()));
            }
        }

        let token_clone = self.access_token.clone();
        Box::new(self.fetch_token().and_then(move |token| {
            token_clone.borrow_mut().replace(token.clone());
            ok(token)
        }))
    }

    fn fetch_token(&mut self) -> Box<Future<Item = AccessToken, Error = Error>> {
        match self.create_jwt() {
            Err(error) => Box::new(err(error)),
            Ok(token) => {
                let mut params = HashMap::new();
                params.insert("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
                params.insert("assertion", &token);
                let request = self.http.post(TOKEN_URL).form(&params);
                let token_fut = request
                    .send()
                    .map_err(|err| Error::from(err))
                    .and_then(|response| Self::parse_response(response));
                Box::new(token_fut)
            }
        }
    }

    fn parse_response(mut response: Response) -> impl Future<Item = AccessToken, Error = Error> {
        response
            .json::<TokenResponse>()
            .map_err(|err| Error::from(err))
            .and_then(|response| {
                Ok(AccessToken {
                    value: response.access_token,
                    expires: SystemTime::now() + Duration::from_secs(response.expires_in),
                })
            })
    }

    fn create_jwt(&self) -> Result<String, Error> {
        let header = Header::new(Algorithm::RS256);
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let exp = iat.add(Duration::from_secs(60 * 60));
        let claims = Claims {
            iss: self.credentials.client_email.clone(),
            scope: self.scopes.clone(),
            aud: TOKEN_URL.to_owned(),
            exp: exp.as_secs(),
            iat: iat.as_secs(),
        };
        let key = self.credentials.private_key.private_key_to_der()?;
        let token = jsonwebtoken::encode(&header, &claims, &key)?;
        Ok(token)
    }
}
