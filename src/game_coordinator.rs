use crate::connection::{ConnectionImpl, ConnectionTrait, MessageFilter, MessageSender};
use crate::message::EncodableMessage;
use crate::net::{decode_kind, NetMessageHeader, RawNetMessage};
use crate::session::Session;
use crate::{Connection, NetworkError};
use futures_util::future::select;
use protobuf::Message;
use std::fmt::{Debug, Formatter};
use std::pin::pin;
use std::time::Duration;
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::steammessages_clientserver::cmsg_client_games_played::GamePlayed;
use steam_vent_proto::steammessages_clientserver::CMsgClientGamesPlayed;
use steam_vent_proto::steammessages_clientserver_2::CMsgGCClient;
use steam_vent_proto::steammessages_clientserver_login::CMsgClientHello;
use steam_vent_proto::{MsgKindEnum, RpcMessage, RpcMessageWithKind};
use tokio::spawn;
use tokio::sync::mpsc::channel;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::debug;

pub struct GameCoordinator {
    app_id: u32,
    filter: MessageFilter,
    sender: MessageSender,
    session: Session,
    timeout: Duration,
}

/// While these kinds are consistent between games, they are not defined in the generic steam protobufs.
/// We define them here, so we can implement the game coordinator without requiring the protobufs from a game
#[repr(i32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum GCMsgKind {
    #[default]
    Invalid = 0,
    k_EMsgGCClientWelcome = 4004,
    k_EMsgGCServerWelcome = 4005,
    k_EMsgGCClientHello = 4006,
    k_EMsgGCServerHello = 4007,
}

impl protobuf::Enum for GCMsgKind {
    const NAME: &'static str = "GCMsgKind";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(v: i32) -> Option<Self> {
        match v {
            4004 => Some(Self::k_EMsgGCClientWelcome),
            4005 => Some(Self::k_EMsgGCServerWelcome),
            4006 => Some(Self::k_EMsgGCClientHello),
            4007 => Some(Self::k_EMsgGCServerHello),
            _ => None,
        }
    }

    fn from_str(_s: &str) -> Option<Self> {
        None
    }
}

impl MsgKindEnum for GCMsgKind {}

impl Debug for GameCoordinator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GameCoordinator")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

impl GameCoordinator {
    pub async fn new(connection: &Connection, app_id: u32) -> Result<Self, NetworkError> {
        let (tx, rx) = channel(10);
        let filter = MessageFilter::new(ReceiverStream::new(rx));
        let gc_messages = connection.on::<ClientFromGcMessage>();
        spawn(async move {
            let mut gc_messages = pin!(gc_messages);
            while let Some(gc_message) = gc_messages.next().await {
                if let Ok(message) = gc_message {
                    let (kind, is_protobuf) = decode_kind(message.data.msgtype());
                    debug!(kind = ?kind, is_protobuf, "received gc messages");

                    let payload = message.data.payload();
                    tx.send(RawNetMessage::read(payload.into())).await.ok();
                }
            }
        });

        let gc = GameCoordinator {
            app_id,
            filter,
            sender: connection.sender.clone(),
            session: connection.session.clone().with_app_id(app_id),
            timeout: connection.timeout(),
        };

        connection
            .send_with_kind(
                CMsgClientGamesPlayed {
                    games_played: vec![GamePlayed {
                        game_id: Some(app_id as u64),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                EMsg::k_EMsgClientGamesPlayedWithDataBlob,
            )
            .await?;

        let welcome = gc.wait_welcome();
        let hello_sender = async {
            loop {
                if let Err(e) = gc.send_hello().await {
                    return Result::<(), _>::Err(e);
                };
                sleep(Duration::from_secs(5)).await;
            }
        };
        select(pin!(welcome), pin!(hello_sender)).await;
        Ok(gc)
    }

    async fn send_hello(&self) -> Result<(), NetworkError> {
        if self.session.is_server() {
            self.send_with_kind(CMsgClientHello::default(), GCMsgKind::k_EMsgGCServerHello)
                .await?;
        } else {
            self.send(CMsgClientHello::default()).await?;
        }
        Ok(())
    }

    async fn wait_welcome(&self) -> Result<(), NetworkError> {
        if self.session.is_server() {
            self.filter.one_kind(GCMsgKind::k_EMsgGCServerWelcome)
        } else {
            self.filter.one_kind(GCMsgKind::k_EMsgGCClientWelcome)
        }
        .await
        .map_err(|_| NetworkError::EOF)?;
        Ok(())
    }
}

impl ConnectionImpl for GameCoordinator {
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
    ) -> Result<(), NetworkError> {
        let nested_header = NetMessageHeader::default();
        let mut payload: Vec<u8> = Vec::with_capacity(
            nested_header.encode_size(kind.into(), is_protobuf) + msg.encode_size(),
        );

        nested_header.write(&mut payload, kind, is_protobuf)?;
        msg.write_body(&mut payload)?;
        let data = CMsgGCClient {
            appid: Some(self.app_id),
            msgtype: Some(kind.encode_kind(is_protobuf)),
            payload: Some(payload),
            ..Default::default()
        };

        let msg = RawNetMessage::from_message(header, ClientToGcMessage { data })?;
        self.sender.send_raw(msg).await
    }
}

#[derive(Debug)]
struct ClientToGcMessage {
    data: CMsgGCClient,
}

impl RpcMessageWithKind for ClientToGcMessage {
    type KindEnum = EMsg;
    const KIND: Self::KindEnum = EMsg::k_EMsgClientToGC;
}

impl RpcMessage for ClientToGcMessage {
    fn parse(reader: &mut dyn std::io::Read) -> protobuf::Result<Self> {
        let data = <CMsgGCClient as Message>::parse_from_reader(reader)?;
        Ok(ClientToGcMessage { data })
    }
    fn write(&self, writer: &mut dyn std::io::Write) -> protobuf::Result<()> {
        self.data.write_to_writer(writer)
    }
    fn encode_size(&self) -> usize {
        self.data.compute_size() as usize
    }
}

#[derive(Debug)]
struct ClientFromGcMessage {
    data: CMsgGCClient,
}

impl RpcMessageWithKind for ClientFromGcMessage {
    type KindEnum = EMsg;
    const KIND: Self::KindEnum = EMsg::k_EMsgClientFromGC;
}

impl RpcMessage for ClientFromGcMessage {
    fn parse(reader: &mut dyn std::io::Read) -> protobuf::Result<Self> {
        let data = <CMsgGCClient as Message>::parse_from_reader(reader)?;
        Ok(ClientFromGcMessage { data })
    }
    fn write(&self, writer: &mut dyn std::io::Write) -> protobuf::Result<()> {
        self.data.write_to_writer(writer)
    }
    fn encode_size(&self) -> usize {
        self.data.compute_size() as usize
    }
}
