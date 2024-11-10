use super::Result;
use crate::connection::{ConnectionImpl, MessageFilter, MessageSender};
use crate::message::{flatten_multi, EncodableMessage};
use crate::net::{NetMessageHeader, RawNetMessage};
use crate::session::{hello, Session};
use crate::transport::websocket::connect;
use crate::{ConnectionError, NetworkError, ServerList};
use bytes::BytesMut;
use futures_util::{Sink, SinkExt, Stream};
use std::fmt::{Debug, Formatter};
use std::future::ready;
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::steammessages_clientserver_login::CMsgClientHeartBeat;
use steam_vent_proto::MsgKindEnum;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio::{select, spawn};
use tokio_stream::StreamExt;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, error};

#[derive(Clone)]
pub(crate) struct RawConnection {
    pub session: Session,
    pub filter: MessageFilter,
    pub timeout: Duration,
    pub sender: MessageSender,
    heartbeat_cancellation_token: CancellationToken,
    _heartbeat_drop_guard: Arc<DropGuard>,
}

impl Debug for RawConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawConnection").finish_non_exhaustive()
    }
}

impl RawConnection {
    pub async fn connect(server_list: &ServerList) -> Result<Self, ConnectionError> {
        let (sender, receiver) = connect(&server_list.pick_ws()).await?;
        Self::from_sender_receiver(sender, receiver).await
    }

    pub async fn from_sender_receiver<
        Sender: Sink<BytesMut, Error = NetworkError> + Send + 'static,
        Receiver: Stream<Item = Result<BytesMut>> + Send + 'static,
    >(
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Self, ConnectionError> {
        let sender = sender.with(|msg: RawNetMessage| ready(Ok(msg.into_bytes())));
        let receiver = flatten_multi(receiver.map(|res| res.and_then(RawNetMessage::read)));

        let filter = MessageFilter::new(receiver);
        let heartbeat_cancellation_token = CancellationToken::new();
        let mut connection = RawConnection {
            session: Session::default(),
            filter,
            sender: MessageSender {
                write: Arc::new(Mutex::new(Box::pin(sender))),
            },
            timeout: Duration::from_secs(10),
            heartbeat_cancellation_token: heartbeat_cancellation_token.clone(),
            // We just store a drop guard using an `Arc` here, so dropping the last clone of `Connection` will cancel the heartbeat task.
            _heartbeat_drop_guard: Arc::new(heartbeat_cancellation_token.drop_guard()),
        };
        hello(&mut connection).await?;
        Ok(connection)
    }

    pub fn setup_heartbeat(&self) {
        let sender = self.sender.clone();
        let interval = self.session.heartbeat_interval;
        let header = NetMessageHeader {
            session_id: self.session.session_id,
            steam_id: self.session().steam_id,
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
}

impl ConnectionImpl for RawConnection {
    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn filter(&self) -> &MessageFilter {
        &self.filter
    }

    fn session(&self) -> &Session {
        &self.session
    }

    async fn raw_send_with_kind<Msg: EncodableMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
        is_protobuf: bool,
    ) -> Result<()> {
        let msg = RawNetMessage::from_message_with_kind(header, msg, kind, is_protobuf)?;
        self.sender.send_raw(msg).await
    }
}
