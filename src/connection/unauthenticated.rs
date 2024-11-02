use super::raw::RawConnection;
use super::{ReadonlyConnection, Result};
use crate::auth::{begin_password_auth, AuthConfirmationHandler, GuardDataStore};
use crate::message::{ServiceMethodMessage, ServiceMethodResponseMessage};
use crate::net::{NetMessageHeader, RawNetMessage};
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, login};
use crate::{Connection, ConnectionError, NetMessage, NetworkError, ServerList};
use futures_util::future::{select, Either};
use futures_util::Stream;
use futures_util::{FutureExt, Sink};
use std::future::Future;
use std::pin::pin;
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::{AccountType, SteamID};
use tokio::time::timeout;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::{debug, error};

/// A Connection that hasn't been authentication yet
pub struct UnAuthenticatedConnection(RawConnection);

impl UnAuthenticatedConnection {
    /// Create a connection from a sender, receiver pair.
    ///
    /// This allows customizing the transport used by the connection. For example to customize the
    /// TLS configuration, use an existing websocket client or use a proxy.
    pub async fn from_sender_receiver<
        Sender: Sink<RawNetMessage, Error = NetworkError> + Send + 'static,
        Receiver: Stream<Item = Result<RawNetMessage>> + Send + 'static,
    >(
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Self, ConnectionError> {
        Ok(UnAuthenticatedConnection(
            RawConnection::from_sender_receiver(sender, receiver).await?,
        ))
    }

    /// Connect to a server from the server list using the default websocket transport
    pub async fn connect(server_list: &ServerList) -> Result<Self, ConnectionError> {
        Ok(UnAuthenticatedConnection(
            RawConnection::connect(server_list).await?,
        ))
    }

    /// Start an anonymous client session with this connection
    pub async fn anonymous(self) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        raw.session = anonymous(&raw, AccountType::AnonUser).await?;
        raw.setup_heartbeat();
        let connection = Connection::new(raw);

        Ok(connection)
    }

    /// Start an anonymous server session with this connection
    pub async fn anonymous_server(self) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        raw.session = anonymous(&raw, AccountType::AnonGameServer).await?;
        raw.setup_heartbeat();
        let connection = Connection::new(raw);

        Ok(connection)
    }

    /// Start a client session with this connection
    pub async fn login<H: AuthConfirmationHandler, G: GuardDataStore>(
        self,
        account: &str,
        password: &str,
        mut guard_data_store: G,
        confirmation_handler: H,
    ) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        let guard_data = guard_data_store.load(account).await.unwrap_or_else(|e| {
            error!(error = ?e, "failed to retrieve guard data");
            None
        });
        if guard_data.is_some() {
            debug!(account, "found stored guard data");
        }
        let begin = begin_password_auth(&mut raw, account, password, guard_data.as_deref()).await?;
        let steam_id = SteamID::from(begin.steam_id());

        let allowed_confirmations = begin.allowed_confirmations();

        let tokens = match select(
            pin!(confirmation_handler.handle_confirmation(&allowed_confirmations)),
            pin!(begin.poll().wait_for_tokens(&raw)),
        )
        .await
        {
            Either::Left((confirmation_action, tokens_fut)) => {
                if let Some(confirmation_action) = confirmation_action {
                    begin.submit_confirmation(&raw, confirmation_action).await?;
                    tokens_fut.await?
                } else if begin.action_required() {
                    return Err(ConnectionError::UnsupportedConfirmationAction(
                        allowed_confirmations.clone(),
                    ));
                } else {
                    tokens_fut.await?
                }
            }
            Either::Right((tokens, _)) => tokens?,
        };

        if let Some(guard_data) = tokens.new_guard_data {
            if let Err(e) = guard_data_store.store(account, guard_data).await {
                error!(error = ?e, "failed to store guard data");
            }
        }

        raw.session = login(
            &mut raw,
            account,
            steam_id,
            // yes we send the refresh token as access token, yes it makes no sense, yes this is actually required
            tokens.refresh_token.as_ref(),
        )
        .await?;
        raw.setup_heartbeat();
        let connection = Connection::new(raw);

        Ok(connection)
    }
}

/// Listen for messages before starting authentication
impl ReadonlyConnection for UnAuthenticatedConnection {
    fn on_notification<T: ServiceMethodRequest>(&self) -> impl Stream<Item = Result<T>> + 'static {
        BroadcastStream::new(self.0.filter.on_notification(T::REQ_NAME))
            .filter_map(|res| res.ok())
            .map(|raw| raw.into_notification())
    }

    fn one_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T)>> + 'static {
        // async block instead of async fn, so we don't have to tie the lifetime of the returned future
        // to the lifetime of &self
        let fut = self.0.filter.one_kind(T::KIND);
        async move {
            let raw = fut.await.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        }
    }

    fn one<T: NetMessage + 'static>(&self) -> impl Future<Output = Result<T>> + 'static {
        self.one_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    fn on_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<(NetMessageHeader, T)>> + 'static {
        BroadcastStream::new(self.0.filter.on_kind(T::KIND)).map(|raw| {
            let raw = raw.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        })
    }

    fn on<T: NetMessage + 'static>(&self) -> impl Stream<Item = Result<T>> + 'static {
        self.on_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }
}

pub(crate) async fn service_method_un_authenticated<Msg: ServiceMethodRequest>(
    connection: &RawConnection,
    msg: Msg,
) -> Result<Msg::Response> {
    let header = connection.session.header(true);
    let recv = connection.filter.on_job_id(header.source_job_id);
    let msg = RawNetMessage::from_message_with_kind(
        header,
        ServiceMethodMessage(msg),
        EMsg::k_EMsgServiceMethodCallFromClientNonAuthed,
        true,
    )?;
    connection.sender.send_raw(msg).await?;
    let message = timeout(connection.timeout, recv)
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(|_| NetworkError::Timeout)?
        .into_message::<ServiceMethodResponseMessage>()?;
    message.into_response::<Msg>()
}
