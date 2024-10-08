use crate::auth::{ConfirmationError, ConfirmationMethod};
use crate::connection::{Connection, ConnectionTrait};
use crate::eresult::EResult;
use crate::net::{JobId, NetMessageHeader, NetworkError};
use crate::proto::steammessages_base::CMsgIPAddress;
use crate::proto::steammessages_clientserver_login::{
    CMsgClientHello, CMsgClientLogon, CMsgClientLogonResponse,
};
use protobuf::MessageField;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use steam_vent_crypto::CryptError;
use steam_vent_proto::steammessages_base::cmsg_ipaddress;
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

#[derive(Debug, Clone)]
pub struct JobIdCounter(Arc<AtomicU64>);

impl JobIdCounter {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&self) -> JobId {
        JobId(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

impl Default for JobIdCounter {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(1)))
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: i32,
    pub cell_id: u32,
    pub public_ip: Option<IpAddr>,
    pub ip_country_code: Option<String>,
    pub job_id: JobIdCounter,
    pub steam_id: SteamID,
    pub heartbeat_interval: Duration,
    pub app_id: Option<u32>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            session_id: 0,
            cell_id: 0,
            public_ip: None,
            ip_country_code: None,
            job_id: JobIdCounter::default(),
            steam_id: SteamID::from(0),
            heartbeat_interval: Duration::from_secs(15),
            app_id: None,
        }
    }
}

impl Session {
    pub fn header(&self, job: bool) -> NetMessageHeader {
        NetMessageHeader {
            session_id: self.session_id,
            source_job_id: if job { self.job_id.next() } else { JobId::NONE },
            target_job_id: JobId::NONE,
            steam_id: self.steam_id,
            source_app_id: self.app_id,
            ..NetMessageHeader::default()
        }
    }

    pub fn is_server(&self) -> bool {
        self.steam_id.account_type() == AccountType::AnonGameServer
            || self.steam_id.account_type() == AccountType::GameServer
    }

    pub fn with_app_id(mut self, app_id: u32) -> Self {
        self.app_id = Some(app_id);
        self
    }
}

pub async fn anonymous(connection: &mut Connection, account_type: AccountType) -> Result<Session> {
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
        SteamID::new(0, Instance::All, account_type, Universe::Public),
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
        source_job_id: JobId::NONE,
        target_job_id: JobId::NONE,
        steam_id,
        ..NetMessageHeader::default()
    };

    let fut = connection.one_with_header::<CMsgClientLogonResponse>();
    connection.raw_send(header, logon).await?;

    debug!("waiting for login response");
    let (header, response) = fut.await?;
    EResult::from_result(response.eresult()).map_err(LoginError::from)?;
    debug!(steam_id = u64::from(steam_id), "session started");
    Ok(Session {
        session_id: header.session_id,
        cell_id: response.cell_id(),
        public_ip: response.public_ip.ip.as_ref().and_then(|ip| match &ip {
            cmsg_ipaddress::Ip::V4(bits) => Some(IpAddr::V4(Ipv4Addr::from(*bits))),
            cmsg_ipaddress::Ip::V6(bytes) if bytes.len() == 16 => {
                let mut bits = [0u8; 16];
                bits.copy_from_slice(&bytes[..]);
                Some(IpAddr::V6(Ipv6Addr::from(bits)))
            }
            _ => None,
        }),
        ip_country_code: response.ip_country_code.clone(),
        steam_id: header.steam_id,
        job_id: JobIdCounter::default(),
        heartbeat_interval: Duration::from_secs(response.heartbeat_seconds() as u64),
        app_id: None,
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
        source_job_id: JobId::NONE,
        target_job_id: JobId::NONE,
        steam_id: SteamID::from(0),
        ..NetMessageHeader::default()
    };

    conn.raw_send(header, req).await?;
    Ok(())
}
