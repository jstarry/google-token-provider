use failure::Error;
use jsonwebtoken::{Algorithm, Header};
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use reqwest::Client as HTTPClient;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Add;
use std::time::UNIX_EPOCH;
use std::time::{Duration, SystemTime};

const TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v4/token";

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
    access_token: Option<AccessToken>,
}

impl Client {
    pub fn new<'a>(credentials: Credentials, scopes: impl Iterator<Item = &'a str>) -> Client {
        Client {
            credentials,
            scopes: scopes.collect::<Vec<&str>>().join(" "),
            http: HTTPClient::new(),
            access_token: None,
        }
    }

    pub fn get_token(&mut self) -> Result<AccessToken, Error> {
        if let Some(token) = &self.access_token {
            if !token.expired() {
                return Ok(token.clone());
            }
        }

        self.access_token = Some(self.fetch_token()?);
        Ok(self.access_token.clone().unwrap())
    }

    fn fetch_token(&mut self) -> Result<AccessToken, Error> {
        let token = self.create_jwt()?;
        let mut params = HashMap::new();
        params.insert("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        params.insert("assertion", &token);

        self.http
            .post(TOKEN_URL)
            .form(&params)
            .send()
            .map_err(Error::from)
            .and_then(Self::parse_response)
    }

    fn parse_response(mut response: Response) -> Result<AccessToken, Error> {
        response
            .json::<TokenResponse>()
            .map_err(Error::from)
            .map(|response| AccessToken {
                value: response.access_token,
                expires: SystemTime::now() + Duration::from_secs(response.expires_in),
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
