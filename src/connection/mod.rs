mod filter;

use crate::auth::{begin_password_auth, AuthConfirmationHandler, GuardDataStore};
use crate::message::{NetMessage, ServiceMethodMessage, ServiceMethodResponseMessage};
use crate::net::{JobId, NetMessageHeader, NetworkError, RawNetMessage};
use crate::proto::enums_clientserver::EMsg;
use crate::proto::steammessages_clientserver_login::CMsgClientHeartBeat;
use crate::serverlist::ServerList;
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, hello, login, ConnectionError, Session};
use crate::transport::websocket::connect;
pub(crate) use connection_impl::ConnectionImplTrait;
pub(crate) use filter::MessageFilter;
use futures_util::future::{select, Either};
use futures_util::{FutureExt, Sink, SinkExt};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::MsgKindEnum;
use steamid_ng::{AccountType, SteamID};
use tokio::sync::Mutex;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, error, instrument};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

pub(crate) type TransportWriter =
    Arc<Mutex<dyn Sink<RawNetMessage, Error = NetworkError> + Unpin + Send>>;

pub struct Connection {
    pub(crate) session: Session,
    filter: MessageFilter,
    write: TransportWriter,
    timeout: Duration,
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
        let mut connection = Connection {
            session: Session::default(),
            filter,
            write: Arc::new(Mutex::new(write)),
            timeout: Duration::from_secs(10),
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

        debug!(account, "saving guard data");
        if let Err(e) = guard_data_store.store(account, tokens.new_guard_data).await {
            error!(error = ?e, "failed to store guard data");
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
        let write = self.write.clone();
        let interval = self.session.heartbeat_interval;
        let header = NetMessageHeader {
            session_id: self.session.session_id,
            steam_id: self.steam_id(),
            ..NetMessageHeader::default()
        };
        spawn(async move {
            loop {
                sleep(interval).await;
                match RawNetMessage::from_message(header.clone(), CMsgClientHeartBeat::default()) {
                    Ok(msg) => {
                        let mut writer = write.lock().await;
                        if let Err(e) = writer.send(msg).await {
                            error!(error = ?e, "Failed to send heartbeat message");
                        }
                    }
                    Err(e) => {
                        error!(error = ?e, "Failed to prepare heartbeat message")
                    }
                }
            }
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
        self.write.lock().await.send(msg).await?;
        let message = timeout(self.timeout, recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::Timeout)?
            .into_message::<ServiceMethodResponseMessage>()?;
        message.into_response::<Msg>()
    }

    pub(crate) fn writer(&self) -> TransportWriter {
        self.write.clone()
    }
}

pub(crate) mod connection_impl {
    use crate::connection::MessageFilter;
    use crate::net::{JobId, NetMessageHeader};
    use crate::session::Session;
    use crate::{NetMessage, NetworkError};
    use std::fmt::Debug;
    use std::future::Future;
    use std::time::Duration;
    use steam_vent_proto::MsgKindEnum;

    pub trait ConnectionImplTrait: Debug {
        fn get_timeout(&self) -> Duration;
        fn get_filter(&self) -> &MessageFilter;
        fn get_session(&self) -> &Session;
        fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
            &self,
            header: NetMessageHeader,
            msg: Msg,
            kind: K,
        ) -> impl Future<Output = Result<JobId, NetworkError>> + Send;
    }
}

pub trait ConnectionTrait: ConnectionImplTrait + Sync {
    fn on_notification<T: ServiceMethodRequest>(&self) -> impl Stream<Item = Result<T>> + 'static {
        BroadcastStream::new(self.get_filter().on_notification(T::REQ_NAME))
            .filter_map(|res| res.ok())
            .map(|raw| raw.into_notification())
    }

    fn one_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T)>> + 'static {
        // async block instead of async fn so we don't have to tie the lifetime of the returned future
        // to the lifetime of &self
        let fut = self.get_filter().one_kind(T::KIND);
        async move {
            let raw = fut.await.map_err(|_| NetworkError::EOF)?;
            Ok((raw.header.clone(), raw.into_message()?))
        }
    }

    fn one<T: NetMessage + 'static>(&self) -> impl Future<Output = Result<T>> + 'static {
        self.one_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    fn on_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<(NetMessageHeader, T)>> + 'static {
        BroadcastStream::new(self.get_filter().on_kind(T::KIND)).map(|raw| {
            let raw = raw.map_err(|_| NetworkError::EOF)?;
            Ok((raw.header.clone(), raw.into_message()?))
        })
    }

    fn on<T: NetMessage + 'static>(&self) -> impl Stream<Item = Result<T>> + 'static {
        self.on_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    fn service_method<Msg: ServiceMethodRequest>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Msg::Response>> + Send {
        async {
            let header = self.get_session().header(true);
            let recv = self.get_filter().on_job_id(header.source_job_id);
            self.raw_send(header, ServiceMethodMessage(msg)).await?;
            let message = timeout(self.get_timeout(), recv)
                .await
                .map_err(|_| NetworkError::Timeout)?
                .map_err(|_| NetworkError::EOF)?
                .into_message::<ServiceMethodResponseMessage>()?;
            message.into_response::<Msg>()
        }
    }

    fn job<Msg: NetMessage, Rsp: NetMessage>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Rsp>> + Send {
        async {
            let job_id = self.raw_send(self.get_session().header(true), msg).await?;
            let resp = self
                .get_filter()
                .on_job_id(job_id)
                .await
                .map_err(|_| NetworkError::EOF)?;
            resp.into_message()
        }
    }

    #[instrument(skip(msg), fields(kind = ?Msg::KIND))]
    fn send<Msg: NetMessage>(&self, msg: Msg) -> impl Future<Output = Result<()>> + Send {
        async {
            self.raw_send(self.get_session().header(false), msg).await?;
            Ok(())
        }
    }

    #[instrument(skip(msg, kind), fields(kind = ?kind))]
    fn send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<JobId>> + Send {
        let header = self.get_session().header(false);
        self.raw_send_with_kind(header, msg, kind)
    }

    fn raw_send<Msg: NetMessage>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
    ) -> impl Future<Output = Result<JobId>> + Send {
        self.raw_send_with_kind(header, msg, Msg::KIND)
    }
}

impl<C: ConnectionImplTrait + Sync> ConnectionTrait for C {}

impl ConnectionImplTrait for Connection {
    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn get_filter(&self) -> &MessageFilter {
        &self.filter
    }

    fn get_session(&self) -> &Session {
        &self.session
    }

    async fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
    ) -> Result<JobId> {
        let job_id = header.source_job_id;
        let msg = RawNetMessage::from_message_with_kind(header, msg, kind)?;

        self.write.lock().await.send(msg).await?;
        Ok(job_id)
    }
}
