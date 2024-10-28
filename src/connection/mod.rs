mod filter;
pub mod raw;
pub mod unauthenticated;

use crate::auth::{AuthConfirmationHandler, GuardDataStore};
use crate::message::{
    EncodableMessage, NetMessage, ServiceMethodMessage, ServiceMethodResponseMessage,
};
use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::serverlist::ServerList;
use crate::service_method::ServiceMethodRequest;
use crate::session::{ConnectionError, Session};
use async_stream::try_stream;
pub use filter::MessageFilter;
use futures_util::{FutureExt, Sink, SinkExt};
use raw::RawConnection;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::{JobMultiple, MsgKindEnum};
use steamid_ng::SteamID;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tracing::instrument;
pub use unauthenticated::UnAuthenticatedConnection;

pub(crate) type Result<T, E = NetworkError> = std::result::Result<T, E>;

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
pub struct Connection(RawConnection);

impl Debug for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Connection {
    pub(self) fn new(raw: RawConnection) -> Self {
        Self(raw)
    }

    pub async fn anonymous(server_list: &ServerList) -> Result<Self, ConnectionError> {
        UnAuthenticatedConnection::connect(server_list)
            .await?
            .anonymous()
            .await
    }

    pub async fn anonymous_server(server_list: &ServerList) -> Result<Self, ConnectionError> {
        UnAuthenticatedConnection::connect(server_list)
            .await?
            .anonymous_server()
            .await
    }

    pub async fn login<H: AuthConfirmationHandler, G: GuardDataStore>(
        server_list: &ServerList,
        account: &str,
        password: &str,
        guard_data_store: G,
        confirmation_handler: H,
    ) -> Result<Self, ConnectionError> {
        UnAuthenticatedConnection::connect(server_list)
            .await?
            .login(account, password, guard_data_store, confirmation_handler)
            .await
    }

    pub fn steam_id(&self) -> SteamID {
        self.session().steam_id
    }

    pub fn session_id(&self) -> i32 {
        self.session().session_id
    }

    pub fn cell_id(&self) -> u32 {
        self.session().cell_id
    }

    pub fn public_ip(&self) -> Option<IpAddr> {
        self.session().public_ip
    }

    pub fn ip_country_code(&self) -> Option<String> {
        self.session().ip_country_code.clone()
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.0.timeout = timeout;
    }

    pub(crate) fn sender(&self) -> &MessageSender {
        &self.0.sender
    }

    /// Get all messages that haven't been filtered by any of the filters
    ///
    /// Note that at most 32 unprocessed connections are stored and calling
    /// this method clears the buffer
    pub fn take_unprocessed(&self) -> Vec<RawNetMessage> {
        self.0.filter.unprocessed()
    }
}

pub(crate) trait ConnectionImpl: Sync + Debug {
    fn timeout(&self) -> Duration;
    fn filter(&self) -> &MessageFilter;
    fn session(&self) -> &Session;

    fn raw_send_with_kind<Msg: EncodableMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
        is_protobuf: bool,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// A trait for listening for messages coming from steam
pub trait ConnectionListener {
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
}

/// A trait for sending messages to steam
pub trait ConnectionSender {
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

    fn raw_send_with_kind<Msg: EncodableMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
        is_protobuf: bool,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl ConnectionImpl for Connection {
    fn timeout(&self) -> Duration {
        self.0.timeout()
    }

    fn filter(&self) -> &MessageFilter {
        self.0.filter()
    }

    fn session(&self) -> &Session {
        self.0.session()
    }

    async fn raw_send_with_kind<Msg: EncodableMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
        is_protobuf: bool,
    ) -> Result<()> {
        <RawConnection as ConnectionImpl>::raw_send_with_kind(
            &self.0,
            header,
            msg,
            kind,
            is_protobuf,
        )
        .await
    }
}

impl<C: ConnectionImpl> ConnectionListener for C {
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
}

impl<C: ConnectionImpl> ConnectionSender for C {
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
        self.raw_send_with_kind(header, msg, kind, Msg::IS_PROTOBUF)
    }

    fn raw_send<Msg: NetMessage>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
    ) -> impl Future<Output = Result<()>> + Send {
        self.raw_send_with_kind(header, msg, Msg::KIND, Msg::IS_PROTOBUF)
    }

    fn raw_send_with_kind<Msg: EncodableMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
        is_protobuf: bool,
    ) -> impl Future<Output = Result<()>> + Send {
        <Self as ConnectionImpl>::raw_send_with_kind(self, header, msg, kind, is_protobuf)
    }
}
