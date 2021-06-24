use crate::message::{
    flatten_multi, ChannelEncryptRequest, ChannelEncryptResult, ClientEncryptResponse, NetMessage,
};
use crate::proto::steammessages_base::CMsgProtoBufHeader;
use bytemuck::{cast, Pod, Zeroable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use futures_sink::Sink;
use futures_util::future::ready;
use futures_util::sink::SinkExt;
use log::{debug, trace};
use protobuf::{Message, ProtobufEnum};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::{Cursor, Seek, SeekFrom};
use steam_vent_crypto::{generate_session_key, symmetric_decrypt, symmetric_encrypt, CryptError};
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::SteamID;
use thiserror::Error;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

pub const PROTO_MASK: u32 = 0x80000000;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("Invalid message header")]
    InvalidHeader,
    #[error("Invalid message kind {0}")]
    InvalidMessageKind(i32),
    #[error("Failed to perform crypto handshake")]
    CryptoHandshakeFailed,
    #[error("Difference message expected, expected {0:?}, got {1:?}")]
    DifferentMessage(EMsg, EMsg),
    #[error("{0}")]
    MalformedBody(#[from] crate::message::MalformedBody),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptError),
    #[error("Unexpected end of stream")]
    EOF,
}

pub type Result<T, E = NetworkError> = std::result::Result<T, E>;

const MAGIC: [u8; 4] = *b"VT01";

#[derive(Debug, Default, Copy, Clone, Zeroable, Pod)]
#[repr(C)]
pub struct Header {
    length: u32,
    magic: [u8; 4],
}

impl Header {
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            Err(NetworkError::InvalidHeader)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
pub struct NetMessageHeader {
    pub source_job_id: u64,
    pub target_job_id: u64,
    pub steam_id: SteamID,
    pub session_id: i32,
}

impl From<CMsgProtoBufHeader> for NetMessageHeader {
    fn from(header: CMsgProtoBufHeader) -> Self {
        NetMessageHeader {
            source_job_id: header.get_jobid_source(),
            target_job_id: header.get_jobid_target(),
            steam_id: header.get_steamid().into(),
            session_id: header.get_client_sessionid(),
        }
    }
}

impl NetMessageHeader {
    fn read<R: ReadBytesExt + Seek>(mut reader: R) -> std::io::Result<Self> {
        reader.seek(SeekFrom::Current(3))?; // 1 byte (fixed) header size, 2 bytes (fixed) header version
        let target_job_id = reader.read_u64::<LittleEndian>()?;
        let source_job_id = reader.read_u64::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(1))?; // header canary (fixed)
        let steam_id = reader.read_u64::<LittleEndian>()?.into();
        let session_id = reader.read_i32::<LittleEndian>()?;
        Ok(NetMessageHeader {
            source_job_id,
            target_job_id,
            steam_id,
            session_id,
        })
    }

    fn write<W: WriteBytesExt>(
        &self,
        writer: &mut W,
        kind: EMsg,
        proto: bool,
    ) -> std::io::Result<()> {
        if kind == EMsg::k_EMsgChannelEncryptResponse {
            writer.write_u32::<LittleEndian>(kind.value() as u32)?;
        } else if proto {
            trace!("writing header for {:?} protobuf message", kind);
            let mut proto_header = CMsgProtoBufHeader::new();
            writer.write_u32::<LittleEndian>(kind.value() as u32 | PROTO_MASK)?;
            proto_header.set_jobid_target(self.target_job_id);
            proto_header.set_jobid_source(self.source_job_id);
            proto_header.set_steamid(self.steam_id.into());
            proto_header.set_client_sessionid(self.session_id);
            writer.write_u32::<LittleEndian>(proto_header.compute_size())?;
            proto_header.write_to_writer(writer)?;
        } else {
            trace!("writing header for {:?} message", kind);
            writer.write_u32::<LittleEndian>(kind.value() as u32)?;
            writer.write_u8(32)?;
            writer.write_u16::<LittleEndian>(2)?;
            writer.write_u64::<LittleEndian>(self.target_job_id)?;
            writer.write_u64::<LittleEndian>(self.source_job_id)?;
            writer.write_u8(239)?;
            writer.write_u64::<LittleEndian>(self.steam_id.into())?;
            writer.write_i32::<LittleEndian>(self.session_id)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RawNetMessage {
    pub kind: EMsg,
    pub is_protobuf: bool,
    pub header: NetMessageHeader,
    pub data: BytesMut,
}

impl TryFrom<BytesMut> for RawNetMessage {
    type Error = NetworkError;

    fn try_from(mut value: BytesMut) -> Result<Self> {
        let mut reader = Cursor::new(&value);
        let kind = reader
            .read_i32::<LittleEndian>()
            .map_err(|_| NetworkError::InvalidHeader)?;

        let is_protobuf = kind < 0;
        let kind = kind & (!PROTO_MASK) as i32;

        let kind = match steam_vent_proto::enums_clientserver::EMsg::from_i32(kind) {
            Some(kind) => kind,
            None => return Err(NetworkError::InvalidMessageKind(kind)),
        };

        trace!("reading header for {:?} message", kind);

        let (header, body_start) = if is_protobuf {
            let header_length = reader.read_u32::<LittleEndian>()?;
            let header =
                CMsgProtoBufHeader::parse_from_bytes(&value[8..8 + header_length as usize])
                    .map_err(|_| NetworkError::InvalidHeader)?;
            (header.into(), 8 + header_length as usize)
        } else if kind == EMsg::k_EMsgChannelEncryptRequest
            || kind == EMsg::k_EMsgChannelEncryptResult
        {
            let target_job_id = reader.read_u64::<LittleEndian>()?;
            let source_job_id = reader.read_u64::<LittleEndian>()?;
            (
                NetMessageHeader {
                    target_job_id,
                    source_job_id,
                    session_id: 0,
                    steam_id: SteamID::default(),
                },
                4 + 8 + 8,
            )
        } else {
            (
                NetMessageHeader::read(&mut reader)?,
                4 + 3 + 8 + 8 + 1 + 8 + 4,
            )
        };

        value.advance(body_start);
        Ok(RawNetMessage {
            kind,
            is_protobuf,
            header,
            data: value,
        })
    }
}

impl RawNetMessage {
    pub fn read<T: NetMessage>(self) -> Result<(NetMessageHeader, T)> {
        if self.kind == T::KIND {
            let mut reader = Cursor::new(self.data);
            Ok((self.header, T::read_body(&mut reader)?))
        } else {
            Err(NetworkError::DifferentMessage(T::KIND, self.kind))
        }
    }
}

struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = BytesMut;
    type Error = NetworkError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 8 {
            return Ok(None);
        }

        let header_bytes = src[0..8].try_into().unwrap();
        let header = cast::<[u8; 8], Header>(header_bytes);
        header.validate()?;
        trace!("got header for packet of {} bytes", header.length);

        if src.len() < 8 + header.length as usize {
            return Ok(None);
        }

        src.advance(8);
        Ok(Some(src.split_to(header.length as usize)))
    }
}

impl Encoder<BytesMut> for FrameCodec {
    type Error = NetworkError;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(8 + item.len());

        dst.extend_from_slice(&u32::to_le_bytes(item.len() as u32));
        dst.extend_from_slice(&MAGIC);
        dst.extend_from_slice(item.as_ref());
        Ok(())
    }
}

/// Write a message to a Sink
pub async fn encode_message<T: NetMessage, S: Sink<BytesMut, Error = NetworkError> + Unpin>(
    header: &NetMessageHeader,
    message: &T,
    dst: &mut S,
) -> Result<()> {
    debug!("writing raw {:?} message", T::KIND);
    let mut buff = BytesMut::new();
    match message.encode_size() {
        Some(message_size) => {
            let cap = message_size + 4;
            buff.reserve(cap);
            let mut writer = (&mut buff).writer();

            header.write(&mut writer, T::KIND, T::IS_PROTOBUF)?;
            message.write_body(&mut writer)?;
        }
        None => {
            buff.reserve(128);

            let mut writer = (&mut buff).writer();
            header.write(&mut writer, T::KIND, T::IS_PROTOBUF)?;
            message.write_body(&mut writer)?;
        }
    };

    trace!("encoded message({} bytes): {:?}", buff.len(), buff.as_ref());
    dst.send(buff).await?;

    Ok(())
}

pub async fn connect<A: ToSocketAddrs>(
    addr: A,
) -> Result<(
    impl Stream<Item = Result<RawNetMessage>>,
    impl Sink<BytesMut, Error = NetworkError>,
)> {
    let stream = TcpStream::connect(addr).await?;
    let (read, write) = stream.into_split();
    let mut raw_reader = FramedRead::new(read, FrameCodec);
    let mut raw_writer = FramedWrite::new(write, FrameCodec);

    let (_header, encrypt_request) =
        RawNetMessage::try_from(raw_reader.next().await.ok_or(NetworkError::EOF)??)?
            .read::<ChannelEncryptRequest>()?;

    trace!("using nonce: {:?}", encrypt_request.nonce);
    let key = generate_session_key(None);

    trace!("generated session keys: {:?}", key.plain);
    trace!("  encrypted: {:?}", key.encrypted);

    let response = ClientEncryptResponse {
        protocol: encrypt_request.protocol,
        encrypted_key: key.encrypted,
    };
    encode_message(&NetMessageHeader::default(), &response, &mut raw_writer).await?;

    let (_header, encrypt_response) =
        RawNetMessage::try_from(raw_reader.next().await.ok_or(NetworkError::EOF)??)?
            .read::<ChannelEncryptResult>()?;

    if encrypt_response.result != 1 {
        return Err(NetworkError::CryptoHandshakeFailed);
    }

    debug!("crypt handshake complete");
    let key = key.plain;

    Ok((
        flatten_multi(
            raw_reader
                .map(move |res| {
                    res.and_then(move |encrypted| {
                        symmetric_decrypt(encrypted, &key).map_err(Into::into)
                    })
                })
                .map(|raw_result| raw_result.and_then(|raw| raw.try_into())),
        ),
        raw_writer.with(move |raw| ready(Ok(symmetric_encrypt(raw, &key)))),
    ))
}
