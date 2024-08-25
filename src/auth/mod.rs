mod confirmation;
mod guard_data;

use crate::connection::Connection;
use crate::message::NetMessage;
use crate::message::{MalformedBody, ServiceMethodMessage};
use crate::net::NetworkError;
use crate::proto::enums::ESessionPersistence;
use crate::proto::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_AllowedConfirmation, CAuthentication_BeginAuthSessionViaCredentials_Request,
    CAuthentication_BeginAuthSessionViaCredentials_Response, CAuthentication_DeviceDetails,
    CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request, EAuthSessionGuardType,
    EAuthTokenPlatformType,
};
use crate::session::{ConnectionError, LoginError};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
pub use confirmation::*;
pub use guard_data::*;
use num_bigint_dig::BigUint;
use num_traits::Num;
use protobuf::{EnumOrUnknown, MessageField};
use rsa::RsaPublicKey;
use std::time::Duration;
use steam_vent_crypto::encrypt_with_key_pkcs1;
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, info, instrument};

pub(crate) async fn begin_password_auth(
    connection: &mut Connection,
    account: &str,
    password: &str,
    guard_data: Option<&str>,
) -> Result<StartedAuth, ConnectionError> {
    let (pub_key, timestamp) = get_password_rsa(connection, account.into()).await?;
    let encrypted_password =
        encrypt_with_key_pkcs1(&pub_key, password.as_bytes()).map_err(LoginError::InvalidPubKey)?;
    let encoded_password = BASE64_STANDARD.encode(encrypted_password);
    info!(account, "starting credentials login");
    let req = CAuthentication_BeginAuthSessionViaCredentials_Request {
        account_name: Some(account.into()),
        encrypted_password: Some(encoded_password),
        encryption_timestamp: Some(timestamp),
        persistence: Some(EnumOrUnknown::new(
            ESessionPersistence::k_ESessionPersistence_Persistent,
        )),

        // todo: platform types
        website_id: Some("Client".into()),
        device_details: MessageField::some(CAuthentication_DeviceDetails {
            device_friendly_name: Some("DESKTOP-VENT".into()),
            platform_type: Some(EnumOrUnknown::new(
                EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
            )),
            os_type: Some(1),
            ..CAuthentication_DeviceDetails::default()
        }),
        guard_data: guard_data.map(String::from),
        ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
    };
    let res = connection.service_method_un_authenticated(req).await?;
    Ok(StartedAuth::Credentials(res))
}

pub(crate) enum StartedAuth {
    Credentials(CAuthentication_BeginAuthSessionViaCredentials_Response),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfirmationError {
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error("Aborted")]
    Aborted,
}

impl StartedAuth {
    fn raw_confirmations(&self) -> &[CAuthentication_AllowedConfirmation] {
        match self {
            StartedAuth::Credentials(res) => res.allowed_confirmations.as_slice(),
        }
    }

    pub fn allowed_confirmations(&self) -> Vec<ConfirmationMethod> {
        self.raw_confirmations()
            .iter()
            .cloned()
            .map(ConfirmationMethod::from)
            .collect()
    }

    #[allow(dead_code)]
    pub fn action_required(&self) -> bool {
        self.raw_confirmations().iter().any(|method| {
            method.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
        })
    }

    fn client_id(&self) -> u64 {
        match self {
            StartedAuth::Credentials(res) => res.client_id(),
        }
    }

    pub fn steam_id(&self) -> u64 {
        match self {
            StartedAuth::Credentials(res) => res.steamid(),
        }
    }

    fn request_id(&self) -> Vec<u8> {
        match self {
            StartedAuth::Credentials(res) => res.request_id().into(),
        }
    }

    fn interval(&self) -> f32 {
        match self {
            StartedAuth::Credentials(res) => res.interval(),
        }
    }

    pub fn poll(&self) -> PendingAuth {
        PendingAuth {
            interval: self.interval(),
            client_id: self.client_id(),
            request_id: self.request_id(),
        }
    }

    pub async fn submit_confirmation(
        &self,
        connection: &Connection,
        confirmation: ConfirmationAction,
    ) -> Result<(), ConfirmationError> {
        match confirmation {
            ConfirmationAction::GuardToken(token, ty) => {
                let req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request {
                    client_id: Some(self.client_id()),
                    steamid: Some(self.steam_id()),
                    code: Some(token.0),
                    code_type: Some(EnumOrUnknown::new(ty.into())),
                    ..CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::default()
                };
                let _ = connection.service_method_un_authenticated(req).await?;
            }
            ConfirmationAction::None => {}
            ConfirmationAction::Abort => return Err(ConfirmationError::Aborted),
        };
        Ok(())
    }
}

/// The token to send to steam to confirm the login
#[derive(Debug)]
pub struct SteamGuardToken(String);

pub(crate) struct PendingAuth {
    client_id: u64,
    request_id: Vec<u8>,
    interval: f32,
}

impl PendingAuth {
    pub(crate) async fn wait_for_tokens(
        self,
        connection: &Connection,
    ) -> Result<Tokens, NetworkError> {
        loop {
            let mut response = poll_until_info(
                connection,
                self.client_id,
                &self.request_id,
                Duration::from_secs_f32(self.interval),
            )
            .await?;
            if response.has_access_token() {
                return Ok(Tokens {
                    access_token: Token(response.take_access_token()),
                    refresh_token: Token(response.take_refresh_token()),
                    new_guard_data: response.new_guard_data,
                });
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Token(String);

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Tokens {
    #[allow(dead_code)]
    pub access_token: Token,
    pub refresh_token: Token,
    pub new_guard_data: Option<String>,
}

async fn poll_until_info(
    connection: &Connection,
    client_id: u64,
    request_id: &[u8],
    interval: Duration,
) -> Result<CAuthentication_PollAuthSessionStatus_Response, NetworkError> {
    loop {
        let req = CAuthentication_PollAuthSessionStatus_Request {
            client_id: Some(client_id),
            request_id: Some(request_id.into()),
            ..CAuthentication_PollAuthSessionStatus_Request::default()
        };

        let resp = connection.service_method_un_authenticated(req).await?;
        let has_data = resp.has_access_token()
            || resp.has_account_name()
            || resp.has_agreement_session_url()
            || resp.has_had_remote_interaction()
            || resp.has_new_challenge_url()
            || resp.has_new_client_id()
            || resp.has_new_guard_data()
            || resp.has_refresh_token();

        if has_data {
            return Ok(resp);
        }

        sleep(interval).await;
    }
}

#[instrument(skip(connection))]
async fn get_password_rsa(
    connection: &mut Connection,
    account: String,
) -> Result<(RsaPublicKey, u64), NetworkError> {
    debug!("getting password rsa");
    let req = CAuthentication_GetPasswordRSAPublicKey_Request {
        account_name: Some(account),
        ..CAuthentication_GetPasswordRSAPublicKey_Request::default()
    };
    let response = connection.service_method_un_authenticated(req).await?;

    let key_mod =
        BigUint::from_str_radix(response.publickey_mod.as_deref().unwrap_or_default(), 16)
            .map_err(|e| {
                MalformedBody::new(
                    ServiceMethodMessage::<CAuthentication_GetPasswordRSAPublicKey_Request>::KIND,
                    e,
                )
            })?;
    let key_exp =
        BigUint::from_str_radix(response.publickey_exp.as_deref().unwrap_or_default(), 16)
            .map_err(|e| {
                MalformedBody::new(
                    ServiceMethodMessage::<CAuthentication_GetPasswordRSAPublicKey_Request>::KIND,
                    e,
                )
            })?;
    let key = RsaPublicKey::new(key_mod, key_exp).map_err(|e| {
        MalformedBody::new(
            ServiceMethodMessage::<CAuthentication_GetPasswordRSAPublicKey_Request>::KIND,
            e,
        )
    })?;
    Ok((key, response.timestamp.unwrap_or_default()))
}
