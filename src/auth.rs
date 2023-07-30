use crate::connection::Connection;
use crate::net::{NetworkError, RawNetMessage};
use crate::proto::enums::ESessionPersistence;
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_BeginAuthSessionViaCredentials_Request, EAuthTokenPlatformType,
};
use crate::session::{anonymous, get_password_rsa, login, LoginError, Session, SessionError};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use futures_sink::Sink;
use protobuf::EnumOrUnknown;
use steam_vent_crypto::encrypt_with_key_pkcs1;
use tokio_stream::Stream;
use tracing::info;

pub enum LoginState<Read, Write> {
    Complete(LoginStateComplete<Read, Write>),
    SteamGuardRequired(LoginStateSteamGuardRequired<Read, Write>),
}

impl<Read, Write> LoginState<Read, Write>
where
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin + Send + 'static,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin + 'static,
{
    pub async fn anonymous(mut read: Read, mut write: Write) -> Self {
        let result = anonymous(&mut read, &mut write).await;
        LoginState::Complete(LoginStateComplete {
            result,
            read,
            write,
        })
    }

    pub async fn password(
        mut read: Read,
        mut write: Write,
        account: &str,
        password: &str,
    ) -> Result<Self, SessionError> {
        let session = login(&mut read, &mut write, account).await?;
        let mut connection = Connection::from_parts(read, write, session);
        let (pub_key, timestamp) = get_password_rsa(&mut connection, account.into()).await?;
        let encrypted_password = encrypt_with_key_pkcs1(&pub_key, password.as_bytes())
            .map_err(LoginError::InvalidPubKey)?;
        let encoded_password = BASE64_STANDARD.encode(encrypted_password);
        info!(account, "starting credentials login");
        dbg!(encoded_password.len(), password);
        let req = CAuthentication_BeginAuthSessionViaCredentials_Request {
            account_name: Some(account.into()),
            encrypted_password: Some(encoded_password),
            encryption_timestamp: Some(timestamp),

            // todo: platform types
            device_friendly_name: Some("DESKTOP-VENT".into()),
            platform_type: Some(EnumOrUnknown::new(
                EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
            )),
            persistence: Some(EnumOrUnknown::new(
                ESessionPersistence::k_ESessionPersistence_Persistent,
            )),
            website_id: Some("Client".into()),

            ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
        };
        dbg!(&req);
        let res = connection.service_method(req).await?;
        dbg!(res);
        todo!();
    }

    pub fn unwrap(self) -> (Result<Session, SessionError>, Read, Write) {
        match self {
            LoginState::Complete(LoginStateComplete {
                result,
                read,
                write,
            }) => (result, read, write),
            LoginState::SteamGuardRequired(LoginStateSteamGuardRequired {
                read, write, ..
            }) => (Err(LoginError::SteamGuardRequired.into()), read, write),
        }
    }
}

pub struct LoginStateComplete<Read, Write> {
    pub result: Result<Session, SessionError>,
    pub read: Read,
    pub write: Write,
}

pub struct LoginStateSteamGuardRequired<Read, Write> {
    _session: Session,
    read: Read,
    write: Write,
}

impl<Read, Write> LoginStateSteamGuardRequired<Read, Write>
where
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin,
{
    pub fn send_steam_guard(self, _code: SteamGuardToken) -> LoginState<Read, Write> {
        todo!()
    }
}

pub struct SteamGuardToken(String);
