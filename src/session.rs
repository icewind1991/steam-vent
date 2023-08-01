use crate::connection::Connection;
use crate::eresult::EResult;
use crate::net::{NetMessageHeader, NetworkError};
use crate::proto::steammessages_base::CMsgIPAddress;
use crate::proto::steammessages_clientserver_login::{
    CMsgClientHello, CMsgClientLogOff, CMsgClientLoggedOff, CMsgClientLogon,
    CMsgClientLogonResponse,
};
use crate::serverlist::ServerDiscoveryError;
use protobuf::MessageField;
use steam_vent_crypto::CryptError;
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use thiserror::Error;
use tracing::debug;

type Result<T, E = SessionError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Network error: {0:#}")]
    Network(#[from] NetworkError),
    #[error("Login failed: {0:#}")]
    LoginError(#[from] LoginError),
    #[error(transparent)]
    Discovery(#[from] ServerDiscoveryError),
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("unknown error {0}")]
    Unknown(i32),
    #[error("steam guard required")]
    SteamGuardRequired,
    #[error("steam returned an invalid public key: {0:#}")]
    InvalidPubKey(CryptError),
}

#[derive(Default, Debug, Clone)]
pub struct JobIdCounter(u64);

impl JobIdCounter {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    session_id: i32,
    job_id: JobIdCounter,
    pub steam_id: SteamID,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            session_id: 0,
            job_id: JobIdCounter::default(),
            steam_id: SteamID::from(0),
        }
    }
}

impl Session {
    pub fn header(&mut self) -> NetMessageHeader {
        NetMessageHeader {
            session_id: self.session_id,
            source_job_id: self.job_id.next(),
            target_job_id: u64::MAX,
            steam_id: self.steam_id,
            ..NetMessageHeader::default()
        }
    }
}

pub async fn anonymous(conn: &mut Connection) -> Result<Session> {
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

    let header = NetMessageHeader {
        session_id: 0,
        source_job_id: u64::MAX,
        target_job_id: u64::MAX,
        steam_id: SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
        ..NetMessageHeader::default()
    };

    let fut = conn.one::<CMsgClientLogonResponse>();
    conn.send(header, logon).await?;

    let (header, response) = fut.await?;
    EResult::from_result(response.eresult()).map_err(NetworkError::from)?;
    debug!("anonymous session started");
    Ok(Session {
        session_id: header.session_id,
        steam_id: header.steam_id,
        job_id: JobIdCounter::default(),
    })
}

pub async fn login(
    conn: &mut Connection,
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

    let header = NetMessageHeader {
        session_id: 0,
        source_job_id: u64::MAX,
        target_job_id: u64::MAX,
        steam_id,
        ..NetMessageHeader::default()
    };

    let fut = conn.one::<CMsgClientLogonResponse>();
    conn.send(header, logon).await?;

    let (header, response) = fut.await?;
    EResult::from_result(response.eresult()).map_err(NetworkError::from)?;
    debug!(account, "session started");
    Ok(Session {
        session_id: header.session_id,
        steam_id: header.steam_id,
        job_id: JobIdCounter::default(),
    })
}

pub async fn logout(conn: &mut Connection) -> Result<()> {
    let mut ip = CMsgIPAddress::new();
    ip.set_v4(0);

    let logout = CMsgClientLogOff::default();

    let header = conn.prepare();
    let fut = conn.one::<CMsgClientLoggedOff>();
    conn.send(header, logout).await?;

    let (_header, response) = fut.await?;
    EResult::from_result(response.eresult()).map_err(NetworkError::from)?;
    debug!("session logged out");
    Ok(())
}

pub async fn hello(conn: &mut Connection) -> Result<()> {
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
