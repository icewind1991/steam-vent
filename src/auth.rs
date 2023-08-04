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
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use num_bigint_dig::BigUint;
use num_traits::Num;
use protobuf::{EnumOrUnknown, MessageField};
use rsa::RsaPublicKey;
use std::io::{stdin, stdout, Write};
use std::io::{Stdin, Stdout};
use std::time::Duration;
use steam_vent_crypto::encrypt_with_key_pkcs1;
use steamid_ng::SteamID;
use tokio::time::sleep;
use tracing::{debug, info, instrument};

pub(crate) async fn begin_password_auth(
    connection: &mut Connection,
    account: &str,
    password: &str,
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
        ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
    };
    let res = connection.service_method_un_authenticated(req).await?;
    Ok(StartedAuth::Credentials(res))
}

pub(crate) enum StartedAuth {
    Credentials(CAuthentication_BeginAuthSessionViaCredentials_Response),
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
            .map(ConfirmationMethod)
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

    pub async fn submit_confirmation(
        self,
        connection: &mut Connection,
        confirmation: ConfirmationAction,
    ) -> Result<PendingAuth, NetworkError> {
        match confirmation {
            ConfirmationAction::GuardToken(token, ty) => {
                let code_type = match ty {
                    GuardType::Device => EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
                    GuardType::Email => EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
                    GuardType::None => EAuthSessionGuardType::k_EAuthSessionGuardType_None,
                };
                let req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request {
                    client_id: Some(self.client_id()),
                    steamid: Some(self.steam_id()),
                    code: Some(token.0),
                    code_type: Some(EnumOrUnknown::new(code_type)),
                    ..CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::default()
                };
                let _ = connection.service_method_un_authenticated(req).await?;
                Ok(PendingAuth {
                    interval: self.interval(),
                    client_id: self.client_id(),
                    request_id: self.request_id(),
                    steam_id: self.steam_id().into(),
                })
            }
            _ => {
                todo!("non token confirmations not implemented yet")
            }
        }
    }
}

pub struct ConfirmationMethod(CAuthentication_AllowedConfirmation);

impl ConfirmationMethod {
    pub fn confirmation_type(&self) -> &'static str {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => "unknown",
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => "none",
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => "email",
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => "device code",
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                "device confirmation"
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                "email confirmation"
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => "machine token",
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => "machine auth",
        }
    }

    pub fn confirmation_details(&self) -> &str {
        self.0.associated_message()
    }

    pub fn action_required(&self) -> bool {
        self.0.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
    }

    pub fn class(&self) -> ConfirmationMethodClass {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => ConfirmationMethodClass::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => ConfirmationMethodClass::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {
                ConfirmationMethodClass::Code
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                ConfirmationMethodClass::Code
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                ConfirmationMethodClass::Confirmation
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                ConfirmationMethodClass::Confirmation
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => {
                ConfirmationMethodClass::Stored
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => {
                ConfirmationMethodClass::Stored
            }
        }
    }

    pub fn guard_type(&self) -> GuardType {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => GuardType::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => GuardType::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => GuardType::Email,
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => GuardType::Device,
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => GuardType::Device,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => GuardType::Email,
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => GuardType::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => GuardType::None,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum ConfirmationMethodClass {
    Code,
    Confirmation,
    Stored,
    None,
}

#[derive(Debug)]
pub enum ConfirmationAction {
    GuardToken(SteamGuardToken, GuardType),
    NotSupported,
    Abort,
}

#[derive(Debug)]
pub enum GuardType {
    Email,
    Device,
    None,
}

#[async_trait]
pub trait AuthConfirmationHandler {
    async fn handle_confirmation(
        &mut self,
        allowed_confirmations: Vec<ConfirmationMethod>,
    ) -> ConfirmationAction;
}

pub struct ConsoleAuthConfirmationHandler {
    stdin: Stdin,
    stdout: Stdout,
}

impl Default for ConsoleAuthConfirmationHandler {
    fn default() -> Self {
        ConsoleAuthConfirmationHandler {
            stdin: stdin(),
            stdout: stdout(),
        }
    }
}

#[async_trait]
impl AuthConfirmationHandler for ConsoleAuthConfirmationHandler {
    async fn handle_confirmation(
        &mut self,
        allowed_confirmations: Vec<ConfirmationMethod>,
    ) -> ConfirmationAction {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Code {
                writeln!(
                    &mut self.stdout,
                    "{}: {}",
                    method.confirmation_type(),
                    method.confirmation_details()
                )
                .ok();
                let mut buff = String::with_capacity(16);
                self.stdin.read_line(&mut buff).ok();
                let token = SteamGuardToken(buff.trim().to_string());
                return ConfirmationAction::GuardToken(token, method.guard_type());
            }
        }
        ConfirmationAction::NotSupported
    }
}

#[derive(Debug)]
pub struct SteamGuardToken(String);

pub(crate) struct PendingAuth {
    client_id: u64,
    request_id: Vec<u8>,
    interval: f32,
    #[allow(dead_code)]
    pub steam_id: SteamID,
}

impl PendingAuth {
    pub(crate) async fn wait_for_tokens(
        &self,
        connection: &mut Connection,
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
                    new_guard_data: response.take_new_guard_data(),
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
    #[allow(dead_code)]
    pub new_guard_data: String,
}

async fn poll_until_info(
    connection: &mut Connection,
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
