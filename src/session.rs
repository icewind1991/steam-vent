use crate::auth::{ConfirmationError, ConfirmationMethod};
use crate::connection::Connection;
use crate::eresult::EResult;
use crate::net::{NetMessageHeader, NetworkError};
use crate::proto::steammessages_base::CMsgIPAddress;
use crate::proto::steammessages_clientserver_login::{
    CMsgClientHello, CMsgClientLogon, CMsgClientLogonResponse,
};
use crate::serverlist::ServerDiscoveryError;
use protobuf::MessageField;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use steam_vent_crypto::CryptError;
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use thiserror::Error;
use tracing::debug;

type Result<T, E = ConnectionError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConnectionError {
    #[error("Network error: {0:#}")]
    Network(#[from] NetworkError),
    #[error("Login failed: {0:#}")]
    LoginError(#[from] LoginError),
    #[error(transparent)]
    Discovery(#[from] ServerDiscoveryError),
    #[error("Aborted")]
    Aborted,
    #[error("Unsupported confirmation action")]
    UnsupportedConfirmationAction(Vec<ConfirmationMethod>),
}

impl From<ConfirmationError> for ConnectionError {
    fn from(value: ConfirmationError) -> Self {
        match value {
            ConfirmationError::Network(err) => err.into(),
            ConfirmationError::Aborted => ConnectionError::Aborted,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LoginError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("unknown error {0:?}")]
    Unknown(EResult),
    #[error("steam guard required")]
    SteamGuardRequired,
    #[error("steam returned an invalid public key: {0:#}")]
    InvalidPubKey(CryptError),
    #[error("account not available")]
    UnavailableAccount,
    #[error("rate limited")]
    RateLimited,
}

impl From<EResult> for LoginError {
    fn from(value: EResult) -> Self {
        match value {
            EResult::InvalidPassword => LoginError::InvalidCredentials,
            EResult::AccountDisabled
            | EResult::AccountLockedDown
            | EResult::AccountHasBeenDeleted
            | EResult::AccountNotFound => LoginError::InvalidCredentials,
            EResult::RateLimitExceeded
            | EResult::AccountActivityLimitExceeded
            | EResult::LimitExceeded
            | EResult::AccountLimitExceeded => LoginError::RateLimited,
            EResult::AccountLoginDeniedNeedTwoFactor => LoginError::SteamGuardRequired,
            value => LoginError::Unknown(value),
        }
    }
}

#[derive(Default, Debug)]
pub struct JobIdCounter(AtomicU64);

impl JobIdCounter {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub struct Session {
    pub session_id: i32,
    pub job_id: JobIdCounter,
    pub steam_id: SteamID,
    pub heartbeat_interval: Duration,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            session_id: 0,
            job_id: JobIdCounter::default(),
            steam_id: SteamID::from(0),
            heartbeat_interval: Duration::from_secs(15),
        }
    }
}

impl Session {
    pub fn header(&self) -> NetMessageHeader {
        NetMessageHeader {
            session_id: self.session_id,
            source_job_id: self.job_id.next(),
            target_job_id: u64::MAX,
            steam_id: self.steam_id,
            ..NetMessageHeader::default()
        }
    }
}

pub async fn anonymous(connection: &mut Connection) -> Result<Session> {
    let mut ip = CMsgIPAddress::new();
    ip.set_v4(0);

    let logon = CMsgClientLogon {
        protocol_version: Some(65580),
        client_os_type: Some(203),
        anon_user_target_account_name: Some(String::from("anonymous")),
        account_name: Some(String::from("anonymous")),
        supports_rate_limit_response: Some(false),
        obfuscated_private_ip: MessageField::some(ip),
        client_language: Some(String::new()),
        chat_mode: Some(2),
        client_package_version: Some(1771),
        ..CMsgClientLogon::default()
    };

    send_logon(
        connection,
        logon,
        SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
    )
    .await
}

pub async fn login(
    connection: &mut Connection,
    account: &str,
    steam_id: SteamID,
    access_token: &str,
) -> Result<Session> {
    let mut ip = CMsgIPAddress::new();
    ip.set_v4(0);

    let logon = CMsgClientLogon {
        protocol_version: Some(65580),
        client_os_type: Some(203),
        account_name: Some(String::from(account)),
        supports_rate_limit_response: Some(false),
        obfuscated_private_ip: MessageField::some(ip),
        client_language: Some(String::new()),
        machine_name: Some(String::new()),
        steamguard_dont_remember_computer: Some(false),
        chat_mode: Some(2),
        access_token: Some(access_token.into()),
        client_package_version: Some(1771),
        ..CMsgClientLogon::default()
    };

    send_logon(connection, logon, steam_id).await
}

async fn send_logon(
    connection: &mut Connection,
    logon: CMsgClientLogon,
    steam_id: SteamID,
) -> Result<Session> {
    let header = NetMessageHeader {
        session_id: 0,
        source_job_id: u64::MAX,
        target_job_id: u64::MAX,
        steam_id,
        ..NetMessageHeader::default()
    };

    let fut = connection.one::<CMsgClientLogonResponse>();
    connection.send(header, logon).await?;

    let (header, response) = fut.await?;
    EResult::from_result(response.eresult()).map_err(LoginError::from)?;
    debug!(steam_id = u64::from(steam_id), "session started");
    Ok(Session {
        session_id: header.session_id,
        steam_id: header.steam_id,
        job_id: JobIdCounter::default(),
        heartbeat_interval: Duration::from_secs(response.heartbeat_seconds() as u64),
    })
}

pub async fn hello(conn: &mut Connection) -> Result<(), NetworkError> {
    const PROTOCOL_VERSION: u32 = 65580;
    let req = CMsgClientHello {
        protocol_version: Some(PROTOCOL_VERSION),
        ..CMsgClientHello::default()
    };

    let header = NetMessageHeader {
        session_id: 0,
        source_job_id: u64::MAX,
        target_job_id: u64::MAX,
        steam_id: SteamID::from(0),
        ..NetMessageHeader::default()
    };

    conn.send(header, req).await?;
    Ok(())
}
