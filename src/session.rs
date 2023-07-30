use crate::connection::Connection;
use crate::eresult::EResult;
use crate::message::{MalformedBody, NetMessage};
use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::proto::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;
use crate::proto::steammessages_base::CMsgIPAddress;
use crate::proto::steammessages_clientserver_login::CMsgClientLogon;
use crate::serverlist::ServerDiscoveryError;
use futures_util::{Sink, SinkExt};
use num_traits::Num;
use protobuf::MessageField;
use rsa::{BigUint, RsaPublicKey};
use steam_vent_crypto::CryptError;
use steam_vent_proto::steammessages_clientserver_login::CMsgClientLogonResponse;
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use thiserror::Error;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tracing::{debug, instrument, warn};

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

pub async fn anonymous<
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin,
>(
    read: &mut Read,
    write: &mut Write,
) -> Result<Session> {
    login(read, write, "anonymous").await
}

pub async fn login<
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin,
>(
    read: &mut Read,
    write: &mut Write,
    account: &str,
) -> Result<Session> {
    let mut logon = CMsgClientLogon::new();
    logon.set_protocol_version(65580);
    logon.set_client_os_type(203);
    logon.set_anon_user_target_account_name(String::from(account));
    logon.set_should_remember_password(false);
    logon.set_supports_rate_limit_response(false);

    let mut ip = CMsgIPAddress::new();
    ip.set_v4(0);
    logon.obfuscated_private_ip = MessageField::some(ip);
    logon.set_client_language(String::new());
    logon.set_machine_name(String::new());
    logon.set_steamguard_dont_remember_computer(false);
    logon.set_chat_mode(2);

    let header = NetMessageHeader {
        session_id: 0,
        source_job_id: u64::MAX,
        target_job_id: u64::MAX,
        steam_id: SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
        ..NetMessageHeader::default()
    };

    let msg = RawNetMessage::from_message(header, logon)?;
    write.send(msg).await?;

    let (header, response): (_, CMsgClientLogonResponse) = blocking_recv(read).await?;
    EResult::from_result(response.eresult()).map_err(NetworkError::from)?;
    debug!(account, "session started");
    return Ok(Session {
        session_id: header.session_id,
        steam_id: header.steam_id,
        job_id: JobIdCounter::default(),
    });
}

/// Receive a message, throwing away anything else
/// only useful during session setup when we know there are no other requests going on
pub async fn blocking_recv<Msg, Read>(
    read: &mut Read,
) -> Result<(NetMessageHeader, Msg), NetworkError>
where
    Msg: NetMessage,
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
{
    while let Some(result) = read.next().await {
        let msg: RawNetMessage = result?;
        if Msg::KIND == msg.kind {
            return Ok((msg.header.clone(), msg.into_message::<Msg>()?));
        } else {
            warn!(kind = ?msg.kind, "skipping message");
        }
    }
    Err(NetworkError::EOF)
}

#[instrument(skip(connection))]
pub async fn get_password_rsa(
    connection: &mut Connection,
    account: String,
) -> Result<(RsaPublicKey, u64), NetworkError> {
    debug!("getting password rsa");
    let req = CAuthentication_GetPasswordRSAPublicKey_Request {
        account_name: Some(account),
        ..CAuthentication_GetPasswordRSAPublicKey_Request::default()
    };
    let response = connection.service_method(req).await?;
    dbg!(&response);

    let key_mod =
        BigUint::from_str_radix(response.publickey_mod.as_deref().unwrap_or_default(), 32)
            .map_err(|e| {
                MalformedBody::new(CAuthentication_GetPasswordRSAPublicKey_Request::KIND, e)
            })?;
    let key_exp =
        BigUint::from_str_radix(response.publickey_exp.as_deref().unwrap_or_default(), 32)
            .map_err(|e| {
                MalformedBody::new(CAuthentication_GetPasswordRSAPublicKey_Request::KIND, e)
            })?;
    let key = RsaPublicKey::new(key_mod, key_exp).map_err(|e| {
        MalformedBody::new(CAuthentication_GetPasswordRSAPublicKey_Request::KIND, e)
    })?;
    Ok((key, response.timestamp.unwrap_or_default()))
}
