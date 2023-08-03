use crate::auth::{begin_password_auth, AuthConfirmationHandler};
use crate::message::{
    NetMessage, ServiceMethodMessage, ServiceMethodNotification, ServiceMethodResponseMessage,
};
use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::serverlist::ServerList;
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, hello, login, Session, SessionError};
use crate::transport::websocket::connect;
use dashmap::DashMap;
use futures_util::{Sink, SinkExt};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::SteamID;
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
}

impl Connection {
    async fn connect(server_list: ServerList) -> Result<Self, SessionError> {
        let (read, write) = connect(&server_list.pick_ws()).await?;
        let (filter, rest) = MessageFilter::new(read);
        let mut connection = Connection {
            session: Session::default(),
            filter,
            rest,
            write: Box::new(write),
            timeout: Duration::from_secs(10),
        };
        hello(&mut connection).await?;
        Ok(connection)
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
        let begin = begin_password_auth(&mut connection, account, password).await?;
        let steam_id = SteamID::from(begin.steam_id());

        let confirmation_action =
            confirmation_handler.handle_confirmation(begin.allowed_confirmations());
        let pending = begin
            .submit_confirmation(&mut connection, confirmation_action)
            .await?;
        let tokens = pending.wait_for_tokens(&mut connection).await?;
        connection.session = login(
            &mut connection,
            account,
            steam_id,
            // yes we send the refresh token as access token, yes it makes no sense, yes this is actually required
            tokens.refresh_token.as_ref(),
        )
        .await?;

        Ok(connection)
    }

    pub fn steam_id(&self) -> SteamID {
        self.session.steam_id
    }

    fn prepare(&self) -> NetMessageHeader {
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
        self.send(header, ServiceMethodMessage(msg)).await?;
        let message = timeout(self.timeout, recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::Timeout)?
            .into_message::<ServiceMethodResponseMessage>()?;
        message.into_response::<Msg>()
    }

    pub(crate) async fn service_method_un_authenticated<Msg: ServiceMethodRequest>(
        &mut self,
        msg: Msg,
    ) -> Result<Msg::Response> {
        let header = self.prepare();
        let recv = self.filter.on_job_id(header.source_job_id);
        let msg = RawNetMessage::from_message_with_kind(
            header,
            ServiceMethodMessage(msg),
            EMsg::k_EMsgServiceMethodCallFromClientNonAuthed,
        )?;
        self.write.send(msg).await?;
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

    pub fn on<T: ServiceMethodRequest>(&self) -> impl Stream<Item = Result<T>> {
        BroadcastStream::new(self.filter.on_notification(T::REQ_NAME))
            .filter_map(|res| res.ok())
            .map(|raw| raw.into_notification())
    }

    pub fn one<T: NetMessage>(&self) -> impl Future<Output = Result<(NetMessageHeader, T)>> {
        // async block instead of async fn so we don't have to tie the lifetime of the returned future
        // to the lifetime of &self
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
    notification_filters: Arc<DashMap<&'static str, broadcast::Sender<ServiceMethodNotification>>>,
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
            notification_filters: Default::default(),
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
                    } else if message.kind == EMsg::k_EMsgServiceMethod {
                        if let Ok(notification) =
                            message.into_message::<ServiceMethodNotification>()
                        {
                            debug!(
                                job_name = notification.job_name.as_str(),
                                "processing notification"
                            );
                            if let Some(tx) = filter_send
                                .notification_filters
                                .get(notification.job_name.as_str())
                            {
                                tx.send(notification).ok();
                            }
                        }
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

    pub fn on_notification(
        &self,
        job_name: &'static str,
    ) -> broadcast::Receiver<ServiceMethodNotification> {
        let tx = self
            .notification_filters
            .entry(job_name)
            .or_insert_with(|| broadcast::channel(16).0);
        tx.subscribe()
    }

    pub fn one_kind(&self, kind: EMsg) -> oneshot::Receiver<RawNetMessage> {
        let (tx, rx) = oneshot::channel();
        self.oneshot_kind_filters.insert(kind, tx);
        rx
    }
}
