use crate::eresult::EResult;
use crate::message::NetMessage;
use crate::proto::steammessages_base::CMsgProtoBufHeader;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use protobuf::Message;
use std::borrow::Cow;
use std::fmt::Debug;
use std::io::{Cursor, Seek, SeekFrom};
use steam_vent_crypto::CryptError;
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::{MsgKind, MsgKindEnum};
use steamid_ng::SteamID;
use thiserror::Error;
use tracing::{debug, trace};

pub const PROTO_MASK: u32 = 0x80000000;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("Invalid message header")]
    InvalidHeader,
    #[error("Invalid message kind {0}")]
    InvalidMessageKind(i32),
    #[error("Failed to perform crypto handshake")]
    CryptoHandshakeFailed,
    #[error("Different message expected, expected {0:?}, got {1:?}")]
    DifferentMessage(MsgKind, MsgKind),
    #[error("Different service method expected, expected {0:?}, got {1:?}")]
    DifferentServiceMethod(&'static str, String),
    #[error("{0}")]
    MalformedBody(#[from] crate::message::MalformedBody),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptError),
    #[error("Unexpected end of stream")]
    EOF,
    #[error("Response timed out")]
    Timeout,
    #[error("Remote returned an error code: {0:?}")]
    ApiError(EResult),
}

impl From<EResult> for NetworkError {
    fn from(value: EResult) -> Self {
        NetworkError::ApiError(value)
    }
}

pub type Result<T, E = NetworkError> = std::result::Result<T, E>;

/// A unique (per-session) identifier that links request-response pairs
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct JobId(pub(crate) u64);

impl Default for JobId {
    fn default() -> Self {
        JobId::NONE
    }
}

impl JobId {
    pub const NONE: JobId = JobId(u64::MAX);
}

#[derive(Debug, Default, Clone)]
pub struct NetMessageHeader {
    pub source_job_id: JobId,
    pub target_job_id: JobId,
    pub steam_id: SteamID,
    pub session_id: i32,
    pub target_job_name: Option<Cow<'static, str>>,
    pub result: Option<i32>,
    pub source_app_id: Option<u32>,
}

impl From<CMsgProtoBufHeader> for NetMessageHeader {
    fn from(header: CMsgProtoBufHeader) -> Self {
        NetMessageHeader {
            source_job_id: JobId(header.jobid_source()),
            target_job_id: JobId(header.jobid_target()),
            steam_id: header.steamid().into(),
            session_id: header.client_sessionid(),
            target_job_name: header
                .has_target_job_name()
                .then(|| header.target_job_name().to_string().into()),
            result: header.eresult,
            source_app_id: header.routing_appid,
        }
    }
}

impl NetMessageHeader {
    fn read<R: ReadBytesExt + Seek>(
        mut reader: R,
        kind: MsgKind,
        is_protobuf: bool,
    ) -> Result<(Self, usize)> {
        if is_protobuf {
            let header_length = reader.read_u32::<LittleEndian>()?;
            trace!("reading protobuf header of {} bytes", header_length);
            let header = if header_length > 0 {
                let mut bytes = vec![0; header_length as usize];
                let num = reader.read(&mut bytes)?;
                CMsgProtoBufHeader::parse_from_bytes(&bytes[0..num])
                    .map_err(|_| NetworkError::InvalidHeader)?
                    .into()
            } else {
                NetMessageHeader::default()
            };
            Ok((header, 8 + header_length as usize))
        } else if kind == EMsg::k_EMsgChannelEncryptRequest
            || kind == EMsg::k_EMsgChannelEncryptResult
        {
            let target_job_id = reader.read_u64::<LittleEndian>()?;
            let source_job_id = reader.read_u64::<LittleEndian>()?;
            Ok((
                NetMessageHeader {
                    target_job_id: JobId(target_job_id),
                    source_job_id: JobId(source_job_id),
                    session_id: 0,
                    steam_id: SteamID::default(),
                    ..NetMessageHeader::default()
                },
                4 + 8 + 8,
            ))
        } else {
            reader.seek(SeekFrom::Current(3))?; // 1 byte (fixed) header size, 2 bytes (fixed) header version
            let target_job_id = reader.read_u64::<LittleEndian>()?;
            let source_job_id = reader.read_u64::<LittleEndian>()?;
            reader.seek(SeekFrom::Current(1))?; // header canary (fixed)
            let steam_id = reader.read_u64::<LittleEndian>()?.into();
            let session_id = reader.read_i32::<LittleEndian>()?;
            Ok((
                NetMessageHeader {
                    source_job_id: JobId(source_job_id),
                    target_job_id: JobId(target_job_id),
                    steam_id,
                    session_id,
                    target_job_name: None,
                    result: None,
                    source_app_id: None,
                },
                4 + 3 + 8 + 8 + 1 + 8 + 4,
            ))
        }
    }

    pub(crate) fn write<W: WriteBytesExt, K: MsgKindEnum>(
        &self,
        writer: &mut W,
        kind: K,
        proto: bool,
    ) -> std::io::Result<()> {
        if MsgKind::from(kind) == EMsg::k_EMsgChannelEncryptResponse {
            writer.write_u32::<LittleEndian>(kind.value() as u32)?;
        } else if proto {
            trace!("writing header for {:?} protobuf message: {:?}", kind, self);
            let proto_header = self.proto_header(kind.into());
            writer.write_u32::<LittleEndian>(kind.encode_kind(true))?;
            writer.write_u32::<LittleEndian>(proto_header.compute_size() as u32)?;
            proto_header.write_to_writer(writer)?;
        } else {
            trace!("writing header for {:?} message: {:?}", kind, self);
            writer.write_u32::<LittleEndian>(kind.value() as u32)?;
            writer.write_u8(32)?;
            writer.write_u16::<LittleEndian>(2)?;
            writer.write_u64::<LittleEndian>(self.target_job_id.0)?;
            writer.write_u64::<LittleEndian>(self.source_job_id.0)?;
            writer.write_u8(239)?;
            writer.write_u64::<LittleEndian>(self.steam_id.into())?;
            writer.write_i32::<LittleEndian>(self.session_id)?;
        }
        Ok(())
    }

    fn proto_header(&self, kind: MsgKind) -> CMsgProtoBufHeader {
        let mut proto_header = CMsgProtoBufHeader::new();
        if self.source_job_id != JobId::NONE {
            proto_header.set_jobid_source(self.source_job_id.0);
        }
        if self.target_job_id != JobId::NONE {
            proto_header.set_jobid_target(self.target_job_id.0);
        }
        if self.steam_id != SteamID::default() {
            proto_header.set_steamid(
                if kind == EMsg::k_EMsgServiceMethodCallFromClientNonAuthed {
                    0
                } else {
                    self.steam_id.into()
                },
            );
        }
        if self.session_id != 0 {
            proto_header.set_client_sessionid(self.session_id);
        }
        if kind == EMsg::k_EMsgServiceMethodCallFromClientNonAuthed
            || kind == EMsg::k_EMsgServiceMethodCallFromClient
        {
            proto_header.set_realm(1);
        }
        if let Some(target_job_name) = self.target_job_name.as_deref() {
            proto_header.set_target_job_name(target_job_name.into());
        }
        proto_header.routing_appid = self.source_app_id;
        proto_header
    }

    pub fn encode_size(&self, kind: MsgKind, proto: bool) -> usize {
        if kind == EMsg::k_EMsgChannelEncryptResponse {
            4
        } else if proto {
            let proto_header = self.proto_header(kind);
            4 + 4 + proto_header.compute_size() as usize
        } else {
            4 + 1 + 2 + 8 + 8 + 1 + 8 + 4 + 4
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawNetMessage {
    pub kind: MsgKind,
    pub is_protobuf: bool,
    pub header: NetMessageHeader,
    pub data: BytesMut,
    pub(crate) frame_header_buffer: Option<BytesMut>,
    pub(crate) iv_buffer: Option<BytesMut>,
    pub(crate) header_buffer: BytesMut,
}

impl RawNetMessage {
    pub fn read(mut value: BytesMut) -> Result<Self> {
        let mut reader = Cursor::new(&value);
        let kind = reader
            .read_u32::<LittleEndian>()
            .map_err(|_| NetworkError::InvalidHeader)?;

        let is_protobuf = kind & PROTO_MASK == PROTO_MASK;
        let kind = MsgKind((kind & !PROTO_MASK) as i32);

        trace!(
            "reading header for {:?} {}message",
            kind,
            if is_protobuf { "protobuf " } else { "" }
        );

        let header_start = reader.position() as usize;
        let (header, body_start) = NetMessageHeader::read(&mut reader, kind, is_protobuf)?;

        value.advance(header_start);
        let header_buffer = value.split_to(body_start - header_start);

        Ok(RawNetMessage {
            kind,
            is_protobuf,
            header,
            data: value,
            frame_header_buffer: None,
            iv_buffer: None,
            header_buffer,
        })
    }

    pub fn from_message<T: NetMessage>(header: NetMessageHeader, message: T) -> Result<Self> {
        Self::from_message_with_kind(header, message, T::KIND)
    }

    pub fn from_message_with_kind<T: NetMessage, K: MsgKindEnum>(
        mut header: NetMessageHeader,
        message: T,
        kind: K,
    ) -> Result<Self> {
        debug!("writing raw {:?} message", kind);

        message.process_header(&mut header);

        let body_size = message.encode_size();

        // allocate the buffer with extra bytes and split those off
        // this allows later re-joining the bytes and use the space for the frame header and iv
        // without having to copy the message again
        //
        // 8 byte frame header, 16 byte iv, header, body, 16 byte encryption padding
        let mut buff = BytesMut::with_capacity(
            8 + 16 + header.encode_size(kind.into(), T::IS_PROTOBUF) + body_size + 16,
        );
        buff.extend([0; 8 + 16]);
        let frame_header_buffer = buff.split_to(8);
        let iv_buffer = buff.split_to(16);

        {
            let mut writer = (&mut buff).writer();
            header.write(&mut writer, kind, T::IS_PROTOBUF)?;
        }

        let header_buffer = buff.split();
        let mut writer = (&mut buff).writer();
        message.write_body(&mut writer)?;
        trace!("encoded body({} bytes): {:x?}", buff.len(), buff.as_ref());

        Ok(RawNetMessage {
            kind: kind.into(),
            is_protobuf: T::IS_PROTOBUF,
            header,
            data: buff,
            frame_header_buffer: Some(frame_header_buffer),
            iv_buffer: Some(iv_buffer),
            header_buffer,
        })
    }
}

impl RawNetMessage {
    pub fn into_message<T: NetMessage>(self) -> Result<T> {
        if let Some(result) = self.header.result {
            EResult::from_result(result)?;
        }
        if self.kind == T::KIND {
            trace!(
                "reading body of {:?} message({} bytes)",
                self.kind,
                self.data.len()
            );
            let body = T::read_body(self.data, &self.header)?;
            Ok(body)
        } else {
            Err(NetworkError::DifferentMessage(T::KIND.into(), self.kind))
        }
    }
}
