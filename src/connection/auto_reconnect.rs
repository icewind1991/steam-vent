use crate::auth::{AuthConfirmationHandler, GuardDataStore};
use crate::connection::{ConnectionConstruction, ConnectionImpl, MessageFilter, MessageSender};
use crate::net::NetMessageHeader;
use crate::session::Session;
use crate::{Connection, ConnectionError, ConnectionTrait, NetMessage, NetworkError, ServerList};
use futures_util::TryFutureExt;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use steam_vent_proto::MsgKindEnum;
use steamid_ng::AccountType;
use tokio::select;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct AuthDetails<H: AuthConfirmationHandler, G: GuardDataStore> {
    account: String,
    password: String,
    guard_data_store: G,
    confirmation_handler: H,
}

#[derive(Debug, Clone)]
pub enum AuthOrAnon<H: AuthConfirmationHandler, G: GuardDataStore> {
    Auth(AuthDetails<H, G>),
    Anon(AccountType),
}

// #[derive(Clone)]
// struct ConnectionPair {
//     sender: MessageSender,
//     filter: MessageFilter,
// }

// impl Debug for ConnectionPair {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("ConnectionPair").finish_non_exhaustive()
//     }
// }

// TODO
//  Option 1: Replace sender and filter - why did I decide that that was not possible?
//   i think it was because at the low level, we might also be in the login process itself. can that be avoided?
/// Option 2:

#[derive(Clone, Debug)]
pub enum ConnectionState {
    Connecting,
    BackOff,
    Failed,
    Connected(Connection),
}

#[derive(Debug, Clone)]
pub struct AutoReconnectSession<H: AuthConfirmationHandler, G: GuardDataStore> {
    server_list: ServerList,
    timeout: Duration,
    auth: AuthOrAnon<H, G>,
    state: Arc<Mutex<ConnectionState>>,
    retry_cancellation_token: CancellationToken,
}

impl<
        H: AuthConfirmationHandler + Clone + Debug + Sync,
        G: GuardDataStore + Debug + Clone + Sync,
    > ConnectionConstruction for AutoReconnectSession<H, G>
{
    async fn anonymous(
        server_list: &ServerList,
    ) -> crate::connection::Result<Self, ConnectionError> {
        let this = Self {
            server_list: server_list.clone(),
            timeout: Duration::from_secs(10),
            auth: AuthOrAnon::Anon(AccountType::AnonUser),
            state: Arc::new(Mutex::new(ConnectionState::Connecting)),
            retry_cancellation_token: CancellationToken::new(),
        };
        this.reconnect(None).await;
        Ok(this)
    }

    async fn anonymous_server(
        server_list: &ServerList,
    ) -> crate::connection::Result<Self, ConnectionError> {
        let this = Self {
            server_list: server_list.clone(),
            timeout: Duration::from_secs(10),
            auth: AuthOrAnon::Anon(AccountType::AnonGameServer),
            state: Arc::new(Mutex::new(ConnectionState::Connecting)),
            retry_cancellation_token: CancellationToken::new(),
        };
        this.reconnect(None).await;
        Ok(this)
    }

    async fn login<H, G>(
        server_list: &ServerList,
        account: &str,
        password: &str,
        guard_data_store: G,
        confirmation_handler: H,
    ) -> crate::connection::Result<Self, ConnectionError> {
        let this = Self {
            server_list: server_list.clone(),
            timeout: Duration::from_secs(10),
            auth: AuthOrAnon::Auth(AuthDetails {
                account: account.to_string(),
                password: password.to_string(),
                guard_data_store,
                confirmation_handler,
            }),
            state: Arc::new(Mutex::new(ConnectionState::Connecting)),
            retry_cancellation_token: CancellationToken::new(),
        };
        this.reconnect(None).await;
        Ok(this)
    }
}

impl<
        H: AuthConfirmationHandler + Debug + Clone + Sync,
        G: GuardDataStore + Debug + Clone + Sync,
    > ConnectionImpl for AutoReconnectSession<H, G>
{
    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn filter(&self) -> Arc<MessageFilter> {
        Arc::new(self.get_current_connection().filter.clone())
    }

    fn session(&self) -> Arc<Session> {
        Arc::new(self.get_current_connection().session.clone())
    }

    fn sender(&self) -> Arc<MessageSender> {
        Arc::new(self.get_current_connection().sender.clone())
    }
}

impl<
        H: AuthConfirmationHandler + Clone + Debug + Sync,
        G: GuardDataStore + Debug + Clone + Sync,
    > ConnectionTrait for AutoReconnectSession<H, G>
{
}

impl<H: AuthConfirmationHandler + Clone, G: GuardDataStore + Clone> AutoReconnectSession<H, G> {
    fn get_current_connection(&self) -> &Connection {
        if let ConnectionState::Connected(connection) = self.state.lock().unwrap() {
            &connection.clone()
        } else {
            panic!("Invalid connection state")
        }
    }

    async fn get_connection(&self) -> Result<Connection, ConnectionError> {
        match &self.auth {
            AuthOrAnon::Anon(AccountType::AnonUser) => {
                Connection::anonymous(&self.server_list).await
            }
            AuthOrAnon::Anon(AccountType::AnonGameServer) => {
                Connection::anonymous_server(&self.server_list).await
            }
            AuthOrAnon::Auth(auth) => {
                Connection::login(
                    &self.server_list,
                    &auth.account,
                    &auth.password,
                    auth.guard_data_store.clone(),
                    auth.confirmation_handler.clone(),
                )
                .await
            }
            _ => {
                panic!("Invalid user type")
            }
        }
    }

    async fn reconnect(&self, err: Option<ConnectionError>) {
        match err {
            Some(err) => *self.state.lock().unwrap() = ConnectionState::Failed,
            None => *self.state.lock().unwrap() = ConnectionState::Connecting,
        }

        // TODO make back-off exponential with jitter
        let mut current_backoff = Duration::from_secs(0);
        while !self.retry_cancellation_token.is_cancelled() {
            select! {
                _ = sleep(current_backoff) => {},
                _ = self.retry_cancellation_token.cancelled() => {                }
            }
            sleep(current_backoff).await;
            *self.state.lock().unwrap() = ConnectionState::Connecting;
            match self.get_connection().await {
                Ok(connection) => {
                    info!("Acquired new connection");
                    *self.state.lock().unwrap() = ConnectionState::Connected(connection);
                    return;
                }
                Err(e) => {
                    *self.state.lock().unwrap() = ConnectionState::BackOff;
                    current_backoff += Duration::from_secs(5);
                    error!(
                        error = ?e,
                        "Failed to get connection, retrying in {:?}", current_backoff
                    );
                }
            };
        }
        info!("Aborting reconnect loop")
    }
}

impl<H: AuthConfirmationHandler, G: GuardDataStore> Drop for AutoReconnectSession<H, G> {
    fn drop(&mut self) {
        self.retry_cancellation_token.cancel()
    }
}
