mod filter;

use crate::auth::{begin_password_auth, AuthConfirmationHandler, GuardDataStore};
use crate::message::{NetMessage, ServiceMethodMessage, ServiceMethodResponseMessage};
use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::proto::enums_clientserver::EMsg;
use crate::proto::steammessages_clientserver_login::CMsgClientHeartBeat;
use crate::serverlist::ServerList;
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, hello, login, ConnectionError, Session};
use crate::transport::websocket::connect;
use async_stream::try_stream;
pub use filter::MessageFilter;
use futures_util::future::{select, Either};
use futures_util::{FutureExt, Sink, SinkExt};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::{JobMultiple, MsgKindEnum};
use steamid_ng::{AccountType, SteamID};
use tokio::select;
use tokio::sync::Mutex;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, error, instrument};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

type TransportWriter = Arc<Mutex<dyn Sink<RawNetMessage, Error = NetworkError> + Unpin + Send>>;

/// Send raw messages to steam
#[derive(Clone)]
pub struct MessageSender {
    write: TransportWriter,
}

impl MessageSender {
    pub async fn send_raw(&self, raw_message: RawNetMessage) -> Result<()> {
        self.write.lock().await.send(raw_message).await?;
        Ok(())
    }
}

/// A connection to the steam server
#[derive(Clone)]
pub struct Connection {
    pub(crate) session: Session,
    filter: MessageFilter,
    timeout: Duration,
    pub(crate) sender: MessageSender,
    heartbeat_cancellation_token: CancellationToken,
    _heartbeat_drop_guard: Arc<DropGuard>,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Connection {
    async fn connect(server_list: &ServerList) -> Result<Self, ConnectionError> {
        let (read, write) = connect(&server_list.pick_ws()).await?;
        let filter = MessageFilter::new(read);
        let heartbeat_cancellation_token = CancellationToken::new();
        let mut connection = Connection {
            session: Session::default(),
            filter,
            sender: MessageSender {
                write: Arc::new(Mutex::new(write)),
            },
            timeout: Duration::from_secs(10),
            heartbeat_cancellation_token: heartbeat_cancellation_token.clone(),
            // We just store a drop guard using an `Arc` here, so dropping the last clone of `Connection` will cancel the heartbeat task.
            _heartbeat_drop_guard: Arc::new(heartbeat_cancellation_token.drop_guard()),
        };
        hello(&mut connection).await?;
        Ok(connection)
    }

    pub async fn anonymous(server_list: &ServerList) -> Result<Self, ConnectionError> {
        let mut connection = Self::connect(server_list).await?;
        connection.session = anonymous(&mut connection, AccountType::AnonUser).await?;
        connection.setup_heartbeat();

        Ok(connection)
    }

    pub async fn anonymous_server(server_list: &ServerList) -> Result<Self, ConnectionError> {
        let mut connection = Self::connect(server_list).await?;
        connection.session = anonymous(&mut connection, AccountType::AnonGameServer).await?;
        connection.setup_heartbeat();

        Ok(connection)
    }

    pub async fn login<H: AuthConfirmationHandler, G: GuardDataStore>(
        server_list: &ServerList,
        account: &str,
        password: &str,
        mut guard_data_store: G,
        confirmation_handler: H,
    ) -> Result<Self, ConnectionError> {
        let mut connection = Self::connect(server_list).await?;
        let guard_data = guard_data_store.load(account).await.unwrap_or_else(|e| {
            error!(error = ?e, "failed to retrieve guard data");
            None
        });
        if guard_data.is_some() {
            debug!(account, "found stored guard data");
        }
        let begin =
            begin_password_auth(&mut connection, account, password, guard_data.as_deref()).await?;
        let steam_id = SteamID::from(begin.steam_id());

        let allowed_confirmations = begin.allowed_confirmations();

        let tokens = match select(
            pin!(confirmation_handler.handle_confirmation(&allowed_confirmations)),
            pin!(begin.poll().wait_for_tokens(&connection)),
        )
        .await
        {
            Either::Left((confirmation_action, tokens_fut)) => {
                if let Some(confirmation_action) = confirmation_action {
                    begin
                        .submit_confirmation(&connection, confirmation_action)
                        .await?;
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

        connection.session = login(
            &mut connection,
            account,
            steam_id,
            // yes we send the refresh token as access token, yes it makes no sense, yes this is actually required
            tokens.refresh_token.as_ref(),
        )
        .await?;
        connection.setup_heartbeat();

        Ok(connection)
    }

    fn setup_heartbeat(&self) {
        let sender = self.sender.clone();
        let interval = self.session.heartbeat_interval;
        let header = NetMessageHeader {
            session_id: self.session.session_id,
            steam_id: self.steam_id(),
            ..NetMessageHeader::default()
        };
        debug!("Setting up heartbeat with interval {:?}", interval);
        let token = self.heartbeat_cancellation_token.clone();
        spawn(async move {
            loop {
                select! {
                    _ = sleep(interval) => {},
                    _ = token.cancelled() => {
                        break
                    }
                };
                debug!("Sending heartbeat message");
                match RawNetMessage::from_message(header.clone(), CMsgClientHeartBeat::default()) {
                    Ok(msg) => {
                        if let Err(e) = sender.send_raw(msg).await {
                            error!(error = ?e, "Failed to send heartbeat message");
                        }
                    }
                    Err(e) => {
                        error!(error = ?e, "Failed to prepare heartbeat message")
                    }
                }
            }
            debug!("Heartbeat task stopping");
        });
    }

    pub fn steam_id(&self) -> SteamID {
        self.session.steam_id
    }

    pub fn session_id(&self) -> i32 {
        self.session.session_id
    }

    pub fn cell_id(&self) -> u32 {
        self.session.cell_id
    }

    pub fn public_ip(&self) -> Option<IpAddr> {
        self.session.public_ip
    }

    pub fn ip_country_code(&self) -> Option<String> {
        self.session.ip_country_code.clone()
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub(crate) async fn service_method_un_authenticated<Msg: ServiceMethodRequest>(
        &self,
        msg: Msg,
    ) -> Result<Msg::Response> {
        let header = self.session.header(true);
        let recv = self.filter.on_job_id(header.source_job_id);
        let msg = RawNetMessage::from_message_with_kind(
            header,
            ServiceMethodMessage(msg),
            EMsg::k_EMsgServiceMethodCallFromClientNonAuthed,
        )?;
        self.sender.send_raw(msg).await?;
        let message = timeout(self.timeout, recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::Timeout)?
            .into_message::<ServiceMethodResponseMessage>()?;
        message.into_response::<Msg>()
    }
}

pub(crate) trait ConnectionImpl: Sync + Debug {
    fn timeout(&self) -> Duration;
    fn filter(&self) -> &MessageFilter;
    fn session(&self) -> &Session;

    fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send;
}

pub trait ConnectionTrait: Debug {
    fn on_notification<T: ServiceMethodRequest>(&self) -> impl Stream<Item = Result<T>> + 'static;

    /// Wait for one message of a specific kind, also returning the header
    fn one_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T)>> + 'static;

    /// Wait for one message of a specific kind
    fn one<T: NetMessage + 'static>(&self) -> impl Future<Output = Result<T>> + 'static;

    /// Listen to messages of a specific kind, also returning the header
    fn on_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<(NetMessageHeader, T)>> + 'static;

    /// Listen to messages of a specific kind
    fn on<T: NetMessage + 'static>(&self) -> impl Stream<Item = Result<T>> + 'static;

    /// Send a rpc-request to steam, waiting for the matching rpc-response
    fn service_method<Msg: ServiceMethodRequest>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Msg::Response>> + Send;

    /// Send a message to steam, waiting for a response with the same job id
    fn job<Msg: NetMessage, Rsp: NetMessage>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Rsp>> + Send;

    /// Send a message to steam, receiving responses until the response marks that the response is complete
    fn job_multi<Msg: NetMessage, Rsp: NetMessage + JobMultiple>(
        &self,
        msg: Msg,
    ) -> impl Stream<Item = Result<Rsp>> + Send;

    /// Send a message to steam without waiting for a response
    fn send<Msg: NetMessage>(&self, msg: Msg) -> impl Future<Output = Result<()>> + Send;

    /// Send a message to steam without waiting for a response, overwriting the kind of the message
    fn send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send;

    fn raw_send<Msg: NetMessage>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
    ) -> impl Future<Output = Result<()>> + Send;

    fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl ConnectionImpl for Connection {
    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn filter(&self) -> &MessageFilter {
        &self.filter
    }

    fn session(&self) -> &Session {
        &self.session
    }

    async fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
    ) -> Result<()> {
        let msg = RawNetMessage::from_message_with_kind(header, msg, kind)?;
        self.sender.send_raw(msg).await
    }
}

impl<C: ConnectionImpl> ConnectionTrait for C {
    fn on_notification<T: ServiceMethodRequest>(&self) -> impl Stream<Item = Result<T>> + 'static {
        BroadcastStream::new(self.filter().on_notification(T::REQ_NAME))
            .filter_map(|res| res.ok())
            .map(|raw| raw.into_notification())
    }

    fn one_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T)>> + 'static {
        // async block instead of async fn, so we don't have to tie the lifetime of the returned future
        // to the lifetime of &self
        let fut = self.filter().one_kind(T::KIND);
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
        BroadcastStream::new(self.filter().on_kind(T::KIND)).map(|raw| {
            let raw = raw.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        })
    }

    fn on<T: NetMessage + 'static>(&self) -> impl Stream<Item = Result<T>> + 'static {
        self.on_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    async fn service_method<Msg: ServiceMethodRequest>(&self, msg: Msg) -> Result<Msg::Response> {
        let header = self.session().header(true);
        let recv = self.filter().on_job_id(header.source_job_id);
        self.raw_send(header, ServiceMethodMessage(msg)).await?;
        let message = timeout(self.timeout(), recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::EOF)?
            .into_message::<ServiceMethodResponseMessage>()?;
        message.into_response::<Msg>()
    }

    async fn job<Msg: NetMessage, Rsp: NetMessage>(&self, msg: Msg) -> Result<Rsp> {
        let header = self.session().header(true);
        let recv = self.filter().on_job_id(header.source_job_id);
        self.raw_send(header, msg).await?;
        timeout(self.timeout(), recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::EOF)?
            .into_message()
    }

    fn job_multi<Msg: NetMessage, Rsp: NetMessage + JobMultiple>(
        &self,
        msg: Msg,
    ) -> impl Stream<Item = Result<Rsp>> + Send {
        try_stream! {
            let header = self.session().header(true);
            let source_job_id = header.source_job_id;
            let mut recv = self.filter().on_job_id_multi(source_job_id);
            self.raw_send(header, msg).await?;
            loop {
                let msg: Rsp = timeout(self.timeout(), recv.recv())
                    .await
                    .map_err(|_| NetworkError::Timeout)?
                    .ok_or(NetworkError::EOF)?
                    .into_message()?;
                let completed = msg.completed();
                yield msg;
                if completed {
                    break;
                }
            }
            self.filter().complete_job_id_multi(source_job_id);
        }
    }

    #[instrument(skip(msg), fields(kind = ?Msg::KIND))]
    fn send<Msg: NetMessage>(&self, msg: Msg) -> impl Future<Output = Result<()>> + Send {
        self.raw_send(self.session().header(false), msg)
    }

    #[instrument(skip(msg, kind), fields(kind = ?kind))]
    fn send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send {
        let header = self.session().header(false);
        self.raw_send_with_kind(header, msg, kind)
    }

    fn raw_send<Msg: NetMessage>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
    ) -> impl Future<Output = Result<()>> + Send {
        self.raw_send_with_kind(header, msg, Msg::KIND)
    }

    fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send {
        <Self as ConnectionImpl>::raw_send_with_kind(self, header, msg, kind)
    }
}
