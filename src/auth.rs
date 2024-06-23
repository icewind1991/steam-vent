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
use another_steam_totp::generate_auth_code;
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use directories::ProjectDirs;
use futures_util::future::{select, Either};
use num_bigint_dig::BigUint;
use num_traits::Num;
use protobuf::{EnumOrUnknown, MessageField};
use rsa::RsaPublicKey;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fs::{create_dir_all, read_to_string, write};
use std::path::PathBuf;
use std::time::Duration;
use steam_vent_crypto::encrypt_with_key_pkcs1;
use thiserror::Error;
use tokio::io::{
    stdin, stdout, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Stdin, Stdout,
};
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

#[derive(Debug, Clone)]
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
    None,
    Abort,
}

#[derive(Debug)]
pub enum GuardType {
    Email,
    Device,
    None,
}

impl From<GuardType> for EAuthSessionGuardType {
    fn from(value: GuardType) -> Self {
        match value {
            GuardType::Device => EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
            GuardType::Email => EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
            GuardType::None => EAuthSessionGuardType::k_EAuthSessionGuardType_None,
        }
    }
}

#[async_trait]
pub trait AuthConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction>;
}

pub type ConsoleAuthConfirmationHandler = UserProvidedAuthConfirmationHandler<Stdin, Stdout>;

pub struct UserProvidedAuthConfirmationHandler<Read, Write> {
    input: BufReader<Read>,
    output: Write,
}

pub struct SharedSecretAuthConfirmationHandler {
    shared_secret: String,
}

impl SharedSecretAuthConfirmationHandler {
    pub fn new(shared_secret: &str) -> Self {
        SharedSecretAuthConfirmationHandler {
            shared_secret: shared_secret.into(),
        }
    }
}

impl Default for ConsoleAuthConfirmationHandler {
    fn default() -> Self {
        ConsoleAuthConfirmationHandler {
            input: BufReader::new(stdin()),
            output: stdout(),
        }
    }
}

#[async_trait]
impl<Read, Write> AuthConfirmationHandler for UserProvidedAuthConfirmationHandler<Read, Write>
where
    Read: AsyncRead + Unpin + Send + Sync,
    Write: AsyncWrite + Unpin + Send + Sync,
{
    async fn handle_confirmation(
        mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Code {
                let msg = format!(
                    "{}: {}",
                    method.confirmation_type(),
                    method.confirmation_details()
                );
                self.output.write_all(msg.as_bytes()).await.ok();
                self.output.flush().await.ok();
                let mut buff = String::with_capacity(16);
                self.input.read_line(&mut buff).await.ok();
                buff.truncate(buff.trim().len());
                if buff.is_empty() {
                    return Some(ConfirmationAction::Abort);
                } else {
                    let token = SteamGuardToken(buff);
                    return Some(ConfirmationAction::GuardToken(token, method.guard_type()));
                }
            }
        }
        None
    }
}

#[async_trait]
impl AuthConfirmationHandler for SharedSecretAuthConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Code {
                let auth_code = generate_auth_code(self.shared_secret, None)
                    .expect("Could not generate auth code given shared secret.");
                let token = SteamGuardToken(auth_code);
                return Some(ConfirmationAction::GuardToken(token, method.guard_type()));
            }
        }
        None
    }
}

#[derive(Default)]
pub struct DeviceConfirmationHandler;

#[async_trait]
impl AuthConfirmationHandler for DeviceConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Confirmation {
                return Some(ConfirmationAction::None);
            }
        }
        None
    }
}

pub struct EitherConfirmationHandler<Left, Right> {
    left: Left,
    right: Right,
}

impl<Left, Right> EitherConfirmationHandler<Left, Right> {
    pub fn new(left: Left, right: Right) -> Self {
        Self { left, right }
    }
}

#[async_trait]
impl<Left, Right> AuthConfirmationHandler for EitherConfirmationHandler<Left, Right>
where
    Left: AuthConfirmationHandler + Send + Sync,
    Right: AuthConfirmationHandler + Send + Sync,
{
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        match select(
            self.left.handle_confirmation(allowed_confirmations),
            self.right.handle_confirmation(allowed_confirmations),
        )
        .await
        {
            Either::Left((left_result, right_fut)) => {
                if !matches!(left_result, None | Some(ConfirmationAction::None)) {
                    left_result
                } else {
                    right_fut.await
                }
            }
            Either::Right((right_result, left_fut)) => {
                if !matches!(right_result, None | Some(ConfirmationAction::None)) {
                    right_result
                } else {
                    left_fut.await
                }
            }
        }
    }
}

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

#[async_trait]
pub trait GuardDataStore {
    type Err: Error;

    async fn store(&mut self, account: &str, machine_token: String) -> Result<(), Self::Err>;

    async fn load(&mut self, account: &str) -> Result<Option<String>, Self::Err>;
}

#[derive(Debug, Error)]
pub enum FileStoreError {
    #[error("error while reading tokens from {}: {:#}", path.display(), err)]
    Read { err: std::io::Error, path: PathBuf },
    #[error("error while writing tokens to {}: {:#}", path.display(), err)]
    Write { err: std::io::Error, path: PathBuf },
    #[error("error while parsing tokens from {}: {:#}", path.display(), err)]
    Json {
        err: serde_json::error::Error,
        path: PathBuf,
    },
    #[error("error while directory {} for tokens: {:#}", path.display(), err)]
    DirCreation { err: std::io::Error, path: PathBuf },
}

/// Store the steam guard data in a json file
pub struct FileGuardDataStore {
    path: PathBuf,
}

impl FileGuardDataStore {
    pub fn new(path: PathBuf) -> Self {
        FileGuardDataStore { path }
    }

    /// Store the machine tokens in the user's cache directory
    pub fn user_cache() -> Self {
        let project_dirs = ProjectDirs::from("nl", "icewind", "steam-vent")
            .expect("user cache not supported on this platform");
        Self::new(project_dirs.cache_dir().join("machine_tokens.json"))
    }

    fn all_tokens(&self) -> Result<HashMap<String, String>, FileStoreError> {
        if !self.path.exists() {
            return Ok(HashMap::default());
        }
        let raw = read_to_string(&self.path).map_err(|err| FileStoreError::Read {
            err,
            path: self.path.clone(),
        })?;
        serde_json::from_str(&raw).map_err(|err| FileStoreError::Json {
            err,
            path: self.path.clone(),
        })
    }

    fn save(&self, tokens: HashMap<String, String>) -> Result<(), FileStoreError> {
        if let Some(parent) = self.path.parent() {
            create_dir_all(parent).map_err(|err| FileStoreError::DirCreation {
                err,
                path: parent.into(),
            })?;
        }

        let raw = serde_json::to_string(&tokens).map_err(|err| FileStoreError::Json {
            err,
            path: self.path.clone(),
        })?;
        write(&self.path, raw).map_err(|err| FileStoreError::Write {
            err,
            path: self.path.clone(),
        })?;
        Ok(())
    }
}

#[async_trait]
impl GuardDataStore for FileGuardDataStore {
    type Err = FileStoreError;

    async fn store(&mut self, account: &str, machine_token: String) -> Result<(), Self::Err> {
        let mut tokens = self.all_tokens()?;
        tokens.insert(account.into(), machine_token);
        self.save(tokens)
    }

    async fn load(&mut self, account: &str) -> Result<Option<String>, Self::Err> {
        let mut tokens = self.all_tokens()?;
        Ok(tokens.remove(account))
    }
}

/// Don't store guard data
pub struct NullGuardDataStore;

#[async_trait]
impl GuardDataStore for NullGuardDataStore {
    type Err = Infallible;

    async fn store(&mut self, _account: &str, _machine_token: String) -> Result<(), Self::Err> {
        Ok(())
    }

    async fn load(&mut self, _account: &str) -> Result<Option<String>, Self::Err> {
        Ok(None)
    }
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
