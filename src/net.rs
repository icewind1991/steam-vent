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
use futures_util::{StreamExt, TryStreamExt};
use protobuf::{Enum, Message};
use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt::Debug;
use std::io::{Cursor, Seek, SeekFrom};
use steam_vent_crypto::{
    generate_session_key, symmetric_decrypt, symmetric_encrypt_with_iv_buffer, CryptError,
};
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::SteamID;
use thiserror::Error;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::{debug, instrument, trace};

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
    #[error("Different message expected, expected {0:?}, got {1:?}")]
    DifferentMessage(EMsg, EMsg),
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

#[derive(Debug, Default, Clone)]
pub struct NetMessageHeader {
    pub source_job_id: u64,
    pub target_job_id: u64,
    pub steam_id: SteamID,
    pub session_id: i32,
    pub target_job_name: Option<Cow<'static, str>>,
}

impl From<CMsgProtoBufHeader> for NetMessageHeader {
    fn from(header: CMsgProtoBufHeader) -> Self {
        NetMessageHeader {
            source_job_id: header.jobid_source(),
            target_job_id: header.jobid_target(),
            steam_id: header.steamid().into(),
            session_id: header.client_sessionid(),
            target_job_name: header
                .has_target_job_name()
                .then(|| header.target_job_name().to_string().into()),
        }
    }
}

impl NetMessageHeader {
    fn read<R: ReadBytesExt + Seek>(
        mut reader: R,
        kind: EMsg,
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
                    target_job_id,
                    source_job_id,
                    session_id: 0,
                    steam_id: SteamID::default(),
                    target_job_name: None,
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
                    source_job_id,
                    target_job_id,
                    steam_id,
                    session_id,
                    target_job_name: None,
                },
                4 + 3 + 8 + 8 + 1 + 8 + 4,
            ))
        }
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
            trace!("writing header for {:?} protobuf message: {:?}", kind, self);
            let mut proto_header = CMsgProtoBufHeader::new();
            writer.write_u32::<LittleEndian>(kind.value() as u32 | PROTO_MASK)?;
            proto_header.set_jobid_target(self.target_job_id);
            proto_header.set_jobid_source(self.source_job_id);
            proto_header.set_steamid(self.steam_id.into());
            proto_header.set_client_sessionid(self.session_id);
            if let Some(target_job_name) = self.target_job_name.as_deref() {
                proto_header.set_target_job_name(target_job_name.into());
            }
            writer.write_u32::<LittleEndian>(proto_header.compute_size() as u32)?;
            proto_header.write_to_writer(writer)?;
        } else {
            trace!("writing header for {:?} message: {:?}", kind, self);
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

    fn encode_size(&self, kind: EMsg, proto: bool) -> usize {
        if kind == EMsg::k_EMsgChannelEncryptResponse {
            4
        } else if proto {
            let mut proto_header = CMsgProtoBufHeader::new();
            proto_header.set_jobid_target(self.target_job_id);
            proto_header.set_jobid_source(self.source_job_id);
            proto_header.set_steamid(self.steam_id.into());
            proto_header.set_client_sessionid(self.session_id);
            if let Some(target_job_name) = self.target_job_name.as_deref() {
                proto_header.set_target_job_name(target_job_name.into());
            }
            4 + 4 + proto_header.compute_size() as usize
        } else {
            4 + 1 + 2 + 8 + 8 + 1 + 8 + 4 + 4
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawNetMessage {
    pub kind: EMsg,
    pub is_protobuf: bool,
    pub header: NetMessageHeader,
    pub data: BytesMut,
    frame_header_buffer: Option<BytesMut>,
    iv_buffer: Option<BytesMut>,
    header_buffer: BytesMut,
}

impl RawNetMessage {
    pub fn read(mut value: BytesMut) -> Result<Self> {
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

    pub fn from_message<T: NetMessage>(mut header: NetMessageHeader, message: T) -> Result<Self> {
        debug!("writing raw {:?} message", T::KIND);

        message.process_header(&mut header);

        let body_size = message.encode_size();

        // allocate the buffer with extra bytes and split those off
        // this allows later re-joining the bytes and use the space for the frame header and iv
        // without having to copy the message again
        //
        // 8 byte frame header, 16 byte iv, header, body, 16 byte encryption padding
        let mut buff = BytesMut::with_capacity(
            8 + 16 + header.encode_size(T::KIND, T::IS_PROTOBUF) + body_size + 16,
        );
        buff.extend([0; 8 + 16]);
        let frame_header_buffer = buff.split_to(8);
        let iv_buffer = buff.split_to(16);

        {
            let mut writer = (&mut buff).writer();
            header.write(&mut writer, T::KIND, T::IS_PROTOBUF)?;
        }

        let header_buffer = buff.split();
        let mut writer = (&mut buff).writer();
        message.write_body(&mut writer)?;
        trace!("encoded body({} bytes): {:?}", buff.len(), buff.as_ref());

        Ok(RawNetMessage {
            kind: T::KIND,
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
        if self.kind == T::KIND {
            trace!(
                "reading body of {:?} message({} bytes)",
                self.kind,
                self.data.len()
            );
            let body = T::read_body(self.data, &self.header)?;
            Ok(body)
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

struct RawMessageEncoder {
    key: [u8; 32],
}

/// Assert that two BytesMut can be unsplit without allocations
#[track_caller]
fn assert_can_unsplit(head: &BytesMut, tail: &BytesMut) {
    let ptr = unsafe { head.as_ref().as_ptr().add(head.len()) };
    debug_assert_eq!(ptr, tail.as_ref().as_ptr());
}

impl Encoder<RawNetMessage> for RawMessageEncoder {
    type Error = NetworkError;

    fn encode(&mut self, mut item: RawNetMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let header_len = item.header_buffer.len();
        let body_len = item.data.len();
        let mut raw = item.header_buffer;

        let empty_body = item.data.is_empty();
        if empty_body {
            // trick unsplit into actually doing something
            item.data.resize(1, 0);
        }
        assert_can_unsplit(&raw, &item.data);
        raw.unsplit(item.data);
        if empty_body {
            raw.truncate(raw.len() - 1);
        }

        trace!(
            "sending raw message({} byte header + {} byte body = {} bytes): {:?}",
            header_len,
            body_len,
            raw.len(),
            raw.as_ref()
        );

        let iv_buffer = item
            .iv_buffer
            .unwrap_or_else(|| BytesMut::from(&[0; 16][..]));
        debug_assert_eq!(16, iv_buffer.len());

        assert_can_unsplit(&iv_buffer, &raw);
        let encrypted = symmetric_encrypt_with_iv_buffer(iv_buffer, raw, &self.key);

        let mut buf = item
            .frame_header_buffer
            .unwrap_or_else(|| BytesMut::from(&[0; 8][..]));
        debug_assert_eq!(8, buf.len());
        buf.clear();
        buf.extend_from_slice(&u32::to_le_bytes(encrypted.len() as u32));
        buf.extend_from_slice(&MAGIC);

        assert_can_unsplit(&buf, &encrypted);
        buf.unsplit(encrypted);

        // dst.extend_from_slice(&buf);
        *dst = buf;

        Ok(())
    }
}

/// Write a message to a Sink
pub async fn encode_message<T: NetMessage, S: Sink<BytesMut, Error = NetworkError> + Unpin>(
    header: &NetMessageHeader,
    message: &T,
    dst: &mut S,
) -> Result<()> {
    let mut buff = BytesMut::new();

    buff.reserve(message.encode_size() + 4);

    let mut writer = (&mut buff).writer();
    header.write(&mut writer, T::KIND, T::IS_PROTOBUF)?;
    message.write_body(&mut writer)?;

    trace!("encoded message({} bytes): {:?}", buff.len(), buff.as_ref());
    dst.send(buff).await?;

    Ok(())
}

#[instrument]
pub async fn connect<A: ToSocketAddrs + Debug>(
    addr: A,
) -> Result<(
    impl Stream<Item = Result<RawNetMessage>>,
    impl Sink<RawNetMessage, Error = NetworkError>,
)> {
    let stream = TcpStream::connect(addr).await?;
    debug!("connected to server");
    let (read, write) = stream.into_split();
    let mut raw_reader = FramedRead::new(read, FrameCodec);
    let mut raw_writer = FramedWrite::new(write, FrameCodec);

    let encrypt_request = RawNetMessage::read(raw_reader.next().await.ok_or(NetworkError::EOF)??)?
        .into_message::<ChannelEncryptRequest>()?;

    trace!("using nonce: {:?}", encrypt_request.nonce);
    let key = generate_session_key(None);

    trace!("generated session keys: {:?}", key.plain);
    trace!("  encrypted: {:?}", key.encrypted);

    let response = ClientEncryptResponse {
        protocol: encrypt_request.protocol,
        encrypted_key: key.encrypted,
    };
    encode_message(&NetMessageHeader::default(), &response, &mut raw_writer).await?;

    let encrypt_response = RawNetMessage::read(raw_reader.next().await.ok_or(NetworkError::EOF)??)?
        .into_message::<ChannelEncryptResult>()?;

    if encrypt_response.result != 1 {
        return Err(NetworkError::CryptoHandshakeFailed);
    }

    debug!("crypt handshake complete");
    let key = key.plain;

    Ok((
        flatten_multi(
            raw_reader
                .and_then(move |encrypted| {
                    let decrypted = symmetric_decrypt(encrypted, &key).map_err(Into::into);
                    if let Ok(bytes) = decrypted.as_ref() {
                        trace!("decrypted message of {} bytes", bytes.len());
                    }
                    ready(decrypted)
                })
                .and_then(|raw| ready(RawNetMessage::read(raw))),
        ),
        FramedWrite::new(raw_writer.into_inner(), RawMessageEncoder { key }),
    ))
}
