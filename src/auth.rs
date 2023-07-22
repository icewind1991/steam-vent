use crate::net::{NetworkError, RawNetMessage};
use crate::session::{anonymous, LoginError, Session, SessionError};
use futures_sink::Sink;
use steamid_ng::SteamID;
use tokio_stream::Stream;

pub enum LoginState<Read, Write> {
    Complete(LoginStateComplete<Read, Write>),
    SteamGuardRequired(LoginStateSteamGuardRequired<Read, Write>),
}

impl<Read, Write> LoginState<Read, Write>
where
    Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin,
    Write: Sink<RawNetMessage, Error = NetworkError> + Unpin,
{
    pub async fn anonymous(mut read: Read, mut write: Write) -> Self {
        let result = anonymous(&mut read, &mut write).await;
        LoginState::Complete(LoginStateComplete {
            result,
            read,
            write,
        })
    }

    pub async fn password(_read: Read, _write: Write, _steam_id: SteamID, _password: &str) -> Self {
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
