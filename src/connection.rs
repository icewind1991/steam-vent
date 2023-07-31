use crate::auth::{begin_password_auth, AuthConfirmationHandler, Tokens};
use crate::message::{NetMessage, ServiceMethodResponseMessage};
use crate::net::{connect, NetMessageHeader, NetworkError, RawNetMessage};
use crate::serverlist::ServerList;
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, hello, login, logout, Session, SessionError};
use dashmap::DashMap;
use futures_sink::Sink;
use futures_util::SinkExt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::spawn;
use tokio::time::timeout;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tracing::debug;

type Result<T, E = NetworkError> = std::result::Result<T, E>;

pub struct Connection {
    pub(crate) session: Session,
    filter: MessageFilter,
    rest: mpsc::Receiver<Result<RawNetMessage>>,
    write: Box<dyn Sink<RawNetMessage, Error = NetworkError> + Unpin>,
    timeout: Duration,
    pub steam_id: SteamID,
    tokens: Option<Tokens>,
}

impl Connection {
    async fn connect(server_list: ServerList) -> Result<Self, SessionError> {
        let (read, write) = connect(server_list.pick()).await?;
        let (filter, rest) = MessageFilter::new(read);
        Ok(Connection {
            session: Session::default(),
            filter,
            rest,
            write: Box::new(write),
            timeout: Duration::from_secs(10),
            steam_id: SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
            tokens: None,
        })
    }

    pub async fn anonymous(server_list: ServerList) -> Result<Self, SessionError> {
        let mut connection = Self::connect(server_list).await?;

        connection.session = anonymous(&mut connection).await?;

        Ok(connection)
    }
    pub async fn login<H: AuthConfirmationHandler>(
        server_list: ServerList,
        account: &str,
        password: &str,
        mut confirmation_handler: H,
    ) -> Result<Self, SessionError> {
        let mut connection = Self::connect(server_list).await?;
        // connection.session = login(&mut connection, account, None).await?;
        hello(&mut connection).await?;
        let begin = begin_password_auth(&mut connection, account, password).await?;

        let confirmation_action =
            confirmation_handler.handle_confirmation(begin.allowed_confirmations());
        let pending = begin
            .submit_confirmation(&mut connection, confirmation_action)
            .await?;
        let tokens = pending.wait_for_tokens(&mut connection).await?;
        connection.session =
            login(&mut connection, account, Some(tokens.access_token.as_ref())).await?;
        connection.tokens = Some(tokens);

        Ok(connection)
    }

    pub fn from_parts<Read, Write>(read: Read, write: Write, session: Session) -> Self
    where
        Read: Stream<Item = Result<RawNetMessage, NetworkError>> + Unpin + Send + 'static,
        Write: Sink<RawNetMessage, Error = NetworkError> + Unpin + 'static,
    {
        let (filter, rest) = MessageFilter::new(read);
        Connection {
            session,
            filter,
            rest,
            write: Box::new(write),
            timeout: Duration::from_secs(10),
            steam_id: SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
            tokens: None,
        }
    }

    pub fn prepare(&mut self) -> NetMessageHeader {
        self.session.header()
    }

    pub async fn send<Msg: NetMessage>(
        &mut self,
        header: NetMessageHeader,
        msg: Msg,
    ) -> Result<()> {
        let msg = RawNetMessage::from_message(header, msg)?;
        self.write.send(msg).await?;
        Ok(())
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub async fn service_method<Msg: ServiceMethodRequest>(
        &mut self,
        msg: Msg,
    ) -> Result<Msg::Response> {
        let header = self.prepare();
        let recv = self.filter.on_job_id(header.source_job_id);
        self.send(header, msg).await?;
        let message = timeout(self.timeout, recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::Timeout)?
            .into_message::<ServiceMethodResponseMessage>()?;
        message.into_response::<Msg>()
    }

    pub async fn next(&mut self) -> Result<RawNetMessage> {
        self.rest.recv().await.ok_or(NetworkError::EOF)?
    }

    pub fn on<T: NetMessage>(&self) -> impl Stream<Item = Result<T>> {
        BroadcastStream::new(self.filter.on_kind(T::KIND))
            .filter_map(|res| res.ok())
            .map(|raw: RawNetMessage| raw.into_message())
    }

    pub fn one<T: NetMessage>(&self) -> impl Future<Output = Result<(NetMessageHeader, T)>> {
        let fut = self.filter.one_kind(T::KIND);
        async move {
            let raw = fut.await.map_err(|_| NetworkError::EOF)?;
            Ok((raw.header.clone(), raw.into_message()?))
        }
    }
}

#[derive(Clone)]
struct MessageFilter {
    job_id_filters: Arc<DashMap<u64, oneshot::Sender<RawNetMessage>>>,
    kind_filters: Arc<DashMap<EMsg, broadcast::Sender<RawNetMessage>>>,
    oneshot_kind_filters: Arc<DashMap<EMsg, oneshot::Sender<RawNetMessage>>>,
}

impl MessageFilter {
    pub fn new<Input: Stream<Item = Result<RawNetMessage>> + Send + Unpin + 'static>(
        mut source: Input,
    ) -> (Self, mpsc::Receiver<Result<RawNetMessage>>) {
        let (rest_tx, rx) = mpsc::channel(16);
        let filter = MessageFilter {
            job_id_filters: Default::default(),
            kind_filters: Default::default(),
            oneshot_kind_filters: Default::default(),
        };

        let filter_send = filter.clone();
        spawn(async move {
            while let Some(res) = source.next().await {
                if let Ok(message) = res {
                    debug!(job_id = message.header.target_job_id, kind = ?message.kind, "processing message");
                    if let Some((_, tx)) = filter_send
                        .job_id_filters
                        .remove(&message.header.target_job_id)
                    {
                        tx.send(message).ok();
                    } else if let Some((_, tx)) =
                        filter_send.oneshot_kind_filters.remove(&message.kind)
                    {
                        tx.send(message).ok();
                    } else if let Some(tx) = filter_send.kind_filters.get(&message.kind) {
                        tx.send(message).ok();
                    } else {
                        rest_tx.send(Ok(message)).await.ok();
                    }
                } else {
                    rest_tx.send(res).await.ok();
                }
            }
        });
        (filter, rx)
    }

    pub fn on_job_id(&self, id: u64) -> oneshot::Receiver<RawNetMessage> {
        let (tx, rx) = oneshot::channel();
        self.job_id_filters.insert(id, tx);
        rx
    }

    pub fn on_kind(&self, kind: EMsg) -> broadcast::Receiver<RawNetMessage> {
        let tx = self
            .kind_filters
            .entry(kind)
            .or_insert_with(|| broadcast::channel(16).0);
        tx.subscribe()
    }

    pub fn one_kind(&self, kind: EMsg) -> oneshot::Receiver<RawNetMessage> {
        let (tx, rx) = oneshot::channel();
        self.oneshot_kind_filters.insert(kind, tx);
        rx
    }
}
