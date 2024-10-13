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
use futures_util::future::{select, Either};
pub use guard_data::*;
use num_bigint_dig::BigUint;
use num_traits::Num;
use protobuf::{EnumOrUnknown, MessageField};
use rsa::RsaPublicKey;
use std::{pin::pin, time::Duration};
use steam_vent_crypto::encrypt_with_key_pkcs1;
use steamid_ng::SteamID;
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument};

pub struct AuthData {
    pub account: String,
    pub password: String,
    pub is_persistent: bool,
    pub website_id: String,
    pub device_friendly_name: String,
    pub platform_type: EAuthTokenPlatformType,
    // todo: platform types
    pub os_type: i32,
    pub guard_data: Option<String>,
}

impl AuthData {
    pub fn new(account: &str, password: &str) -> Self {
        Self {
            account: account.into(),
            password: password.into(),
            is_persistent: false,
            website_id: "Client".to_string(),
            device_friendly_name: "DESKTOP-VENT".to_string(),
            platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
            os_type: 20,
            guard_data: None,
        }
    }

    pub async fn with_guard<G: GuardDataStore>(
        account: &str,
        password: &str,
        guard_data_store: &mut G,
    ) -> Self {
        let mut data = Self::new(account, password);
        data.is_persistent = true;
        data.guard_data = match guard_data_store.load(account).await {
            Ok(guard) => {
                debug!(account, "found stored guard data");
                guard
            }
            Err(e) => {
                error!(error = ?e, "failed to retrieve guard data");
                None
            }
        };
        data
    }
}

pub enum StartedAuth {
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
    pub async fn begin_via_credentials(
        connection: &Connection,
        data: AuthData,
    ) -> Result<Self, ConnectionError> {
        let (pub_key, timestamp) = get_password_rsa(connection, data.account.clone()).await?;
        let encrypted_password = encrypt_with_key_pkcs1(&pub_key, data.password.as_bytes())
            .map_err(LoginError::InvalidPubKey)?;
        let encoded_password = BASE64_STANDARD.encode(encrypted_password);
        info!(data.account, "starting credentials login");
        let req = CAuthentication_BeginAuthSessionViaCredentials_Request {
            account_name: Some(data.account.into()),
            encrypted_password: Some(encoded_password),
            encryption_timestamp: Some(timestamp),
            persistence: Some(EnumOrUnknown::new(if data.is_persistent {
                ESessionPersistence::k_ESessionPersistence_Persistent
            } else {
                ESessionPersistence::k_ESessionPersistence_Ephemeral
            })),
            website_id: Some(data.website_id),
            device_details: MessageField::some(CAuthentication_DeviceDetails {
                device_friendly_name: Some(data.device_friendly_name),
                platform_type: Some(EnumOrUnknown::new(data.platform_type)),
                os_type: Some(data.os_type),
                ..CAuthentication_DeviceDetails::default()
            }),
            guard_data: data.guard_data,
            ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
        };
        let res = connection.service_method_un_authenticated(req).await?;
        Ok(Self::Credentials(res))
    }

    fn raw_confirmations(&self) -> &[CAuthentication_AllowedConfirmation] {
        match self {
            Self::Credentials(res) => res.allowed_confirmations.as_slice(),
        }
    }

    pub fn allowed_confirmations(&self) -> Vec<ConfirmationMethod> {
        self.raw_confirmations()
            .iter()
            .cloned()
            .map(ConfirmationMethod::from)
            .collect()
    }

    fn action_required(&self) -> bool {
        self.raw_confirmations().iter().any(|method| {
            method.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
        })
    }

    fn client_id(&self) -> u64 {
        match self {
            Self::Credentials(res) => res.client_id(),
        }
    }

    pub fn steam_id(&self) -> SteamID {
        match self {
            Self::Credentials(res) => SteamID::from(res.steamid()),
        }
    }

    fn request_id(&self) -> Vec<u8> {
        match self {
            Self::Credentials(res) => res.request_id().into(),
        }
    }

    fn interval(&self) -> f32 {
        match self {
            Self::Credentials(res) => res.interval(),
        }
    }

    fn poll(&self) -> PendingAuth {
        PendingAuth {
            interval: self.interval(),
            client_id: self.client_id(),
            request_id: self.request_id(),
        }
    }

    async fn submit_confirmation(
        &self,
        connection: &Connection,
        confirmation: ConfirmationAction,
    ) -> Result<(), ConfirmationError> {
        match confirmation {
            ConfirmationAction::GuardToken(token, ty) => {
                let req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request {
                    client_id: Some(self.client_id()),
                    steamid: Some(self.steam_id().into()),
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

    pub async fn wait_confirmation<H: AuthConfirmationHandler>(
        &self,
        connection: &Connection,
        confirmation_handler: H,
    ) -> Result<Tokens, ConnectionError> {
        let allowed_confirmations = self.allowed_confirmations();
        let tokens = match select(
            pin!(confirmation_handler.handle_confirmation(&allowed_confirmations)),
            pin!(self.poll().wait_for_tokens(&connection)),
        )
        .await
        {
            Either::Left((confirmation_action, tokens_fut)) => {
                if let Some(confirmation_action) = confirmation_action {
                    self.submit_confirmation(&connection, confirmation_action)
                        .await?;
                    tokens_fut.await?
                } else if self.action_required() {
                    return Err(ConnectionError::UnsupportedConfirmationAction(
                        allowed_confirmations.clone(),
                    ));
                } else {
                    tokens_fut.await?
                }
            }
            Either::Right((tokens, _)) => tokens?,
        };
        Ok(tokens)
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
                    access_token: response.take_access_token(),
                    refresh_token: response.take_refresh_token(),
                    new_guard_data: response.new_guard_data,
                });
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tokens {
    #[allow(dead_code)]
    pub access_token: String,
    pub refresh_token: String,
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
    connection: &Connection,
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
