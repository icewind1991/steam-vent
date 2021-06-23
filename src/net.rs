use crate::message::{
    ChannelEncryptRequest, ChannelEncryptResult, ClientEncryptResponse, Flatten, NetMessage,
};
use crate::proto::steammessages_base::CMsgProtoBufHeader;
use async_stream::try_stream;
use binread::{BinRead, BinReaderExt};
use bytemuck::{cast, Pod, Zeroable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BytesMut};
use log::{debug, trace};
use pin_project_lite::pin_project;
use protobuf::{Message, ProtobufEnum};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::{Cursor, Error, Seek, SeekFrom, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use steam_vent_crypto::{generate_session_key, symmetric_decrypt, symmetric_encrypt, CryptError};
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::SteamID;
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::pin;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, FramedRead};

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

#[derive(Debug, Default, Copy, Clone, BinRead, Zeroable, Pod)]
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
            writer.write_u64::<LittleEndian>(self.target_job_id)?;
            writer.write_u64::<LittleEndian>(self.source_job_id)?;
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

struct FrameDecoder;

impl Decoder for FrameDecoder {
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

pub struct RawSteamWriter {
    tcp: OwnedWriteHalf,
}

impl RawSteamWriter {
    pub async fn write_message<T: NetMessage>(&mut self, message: &T) -> Result<()> {
        debug!("writing raw {:?} message", T::KIND);
        let buff = match message.encode_size() {
            Some(message_size) => {
                let cap = message_size + 8 + 4;
                let mut buff = Vec::with_capacity(cap);

                WriteBytesExt::write_u32::<LittleEndian>(&mut buff, message_size as u32 + 4)?; // +4 for the KIND
                Write::write_all(&mut buff, &MAGIC)?;

                WriteBytesExt::write_i32::<LittleEndian>(&mut buff, T::KIND.value())?;
                message.write_body(&mut buff)?;

                buff
            }
            None => {
                let mut body = Vec::with_capacity(128);
                message.write_body(&mut body)?;

                let message_size = body.len();

                let cap = message_size + 8 + 4;
                let mut buff = Vec::with_capacity(cap);

                WriteBytesExt::write_u32::<LittleEndian>(&mut buff, message_size as u32 + 4)?; // +4 for the KIND
                Write::write_all(&mut buff, &MAGIC)?;

                WriteBytesExt::write_i32::<LittleEndian>(&mut buff, T::KIND.value())?;
                Write::write_all(&mut buff, &body)?;

                buff
            }
        };

        trace!("encoded raw message({} bytes): {:?}", buff.len(), buff);
        self.tcp.write_all(&buff).await?;
        self.tcp.flush().await?;

        Ok(())
    }
}

pin_project! {
    pub struct Decrypter<S> {
        #[pin]
        raw: S,
        key: [u8; 32],
    }
}

impl<S: Stream<Item = Result<BytesMut>>> Stream for Decrypter<S> {
    type Item = Result<BytesMut>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut().project().raw.poll_next(cx).map(|opt| {
            opt.map(|raw_result| {
                raw_result.and_then(|raw| {
                    let key = self.as_mut().project().key;
                    symmetric_decrypt(raw, key).map_err(NetworkError::from)
                })
            })
        })
    }
}

pin_project! {
    pub struct RawMessageReader<S> {
        #[pin]
        raw: S
    }
}

impl<S: Stream<Item = Result<BytesMut>>> Stream for RawMessageReader<S> {
    type Item = Result<RawNetMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut()
            .project()
            .raw
            .poll_next(cx)
            .map(|opt| opt.map(|raw_result| raw_result.and_then(|raw| raw.try_into())))
    }
}

pub struct SteamWriter {
    raw: RawSteamWriter,
    key: [u8; 32],
}

impl SteamWriter {
    pub async fn write<T: NetMessage>(
        &mut self,
        header: &NetMessageHeader,
        message: &T,
    ) -> Result<()> {
        debug!("sending {:?} message", T::KIND);
        trace!("  {:#?}", message);
        let message_size = message.encode_size().unwrap_or(128);
        let mut raw = Vec::with_capacity(64 + message_size);

        header.write(&mut raw, T::KIND, T::IS_PROTOBUF)?;
        message.write_body(&mut raw)?;

        trace!("encoded message({} bytes): {:?}", raw.len(), raw);

        let encrypted = symmetric_encrypt(raw, &self.key)?;

        let mut buff = Vec::with_capacity(encrypted.len() + 8);

        WriteBytesExt::write_u32::<LittleEndian>(&mut buff, encrypted.len() as u32)?;
        Write::write_all(&mut buff, &MAGIC)?;
        Write::write_all(&mut buff, &encrypted)?;

        trace!("writing raw packet({} bytes): {:?}", buff.len(), buff);

        let wrote = self.raw.tcp.write(&buff).await?;
        trace!("wrote {} bytes", wrote);

        self.raw.tcp.flush().await?;

        Ok(())
    }
}

pub async fn connect<A: ToSocketAddrs>(
    addr: A,
) -> Result<(impl Stream<Item = Result<RawNetMessage>>, SteamWriter)> {
    let stream = TcpStream::connect(addr).await?;
    let (read, write) = stream.into_split();
    let mut raw_reader = FramedRead::new(read, FrameDecoder);
    let mut raw_writer = RawSteamWriter { tcp: write };

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
    raw_writer.write_message(&response).await?;

    let (_header, encrypt_response) =
        RawNetMessage::try_from(raw_reader.next().await.ok_or(NetworkError::EOF)??)?
            .read::<ChannelEncryptResult>()?;

    if encrypt_response.result != 1 {
        return Err(NetworkError::CryptoHandshakeFailed);
    }

    debug!("crypt handshake complete");

    Ok((
        Flatten::new(RawMessageReader {
            raw: Decrypter {
                raw: raw_reader,
                key: key.plain,
            },
        }),
        SteamWriter {
            raw: raw_writer,
            key: key.plain,
        },
    ))
}
