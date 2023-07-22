use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::proto::steammessages_base::CMsgIPAddress;
use crate::proto::steammessages_clientserver_login::CMsgClientLogon;
use crate::serverlist::ServerDiscoveryError;
use futures_util::{Sink, SinkExt};
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::steammessages_clientserver_login::CMsgClientLogonResponse;
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use thiserror::Error;
use tokio_stream::Stream;
use tokio_stream::StreamExt;

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
}

impl LoginError {
    fn from_e_result(result: i32) -> Result<(), Self> {
        // https://steam.readthedocs.io/en/latest/api/steam.enums.html#steam.enums.common.EResult
        match result {
            1 => Ok(()),
            5 => Err(LoginError::InvalidCredentials),
            _ => Err(LoginError::Unknown(result)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    session_id: i32,
    last_source_id: u64,
    pub steam_id: SteamID,
}

impl Session {
    pub fn header(&mut self) -> NetMessageHeader {
        self.last_source_id += 1;
        NetMessageHeader {
            session_id: self.session_id,
            source_job_id: self.last_source_id,
            target_job_id: u64::MAX,
            steam_id: self.steam_id,
            target_job_name: None,
        }
    }
}

pub async fn anonymous<
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin,
>(
    read: &mut Read,
    write: &mut Write,
) -> Result<Session> {
    login(
        read,
        write,
        SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
    )
    .await
}

pub async fn login<
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin,
>(
    read: &mut Read,
    write: &mut Write,
    steam_id: SteamID,
) -> Result<Session> {
    let mut logon = CMsgClientLogon::new();
    logon.set_protocol_version(65580);
    logon.set_client_os_type(203);
    logon.set_anon_user_target_account_name(String::from("anonymous"));
    logon.set_should_remember_password(false);
    logon.set_supports_rate_limit_response(false);

    let mut ip = CMsgIPAddress::new();
    ip.set_v4(0);
    logon.set_obfuscated_private_ip(ip);
    logon.set_client_language(String::new());
    logon.set_machine_name(String::new());
    logon.set_steamguard_dont_remember_computer(false);
    logon.set_chat_mode(2);

    let header = NetMessageHeader {
        session_id: 0,
        source_job_id: u64::MAX,
        target_job_id: u64::MAX,
        steam_id,
        target_job_name: None,
    };

    let msg = RawNetMessage::from_message(header, logon)?;
    write.send(msg).await?;

    while let Some(result) = read.next().await {
        let msg: RawNetMessage = result?;
        if let EMsg::k_EMsgClientLogOnResponse = msg.kind {
            let session_id = msg.header.session_id;
            let steam_id = msg.header.steam_id;
            let response = msg.into_message::<CMsgClientLogonResponse>()?;

            LoginError::from_e_result(response.get_eresult())?;
            return Ok(Session {
                session_id,
                steam_id,
                last_source_id: 0,
            });
        }
    }
    Err(NetworkError::EOF.into())
}
