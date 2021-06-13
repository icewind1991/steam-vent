use crate::message::{
    ChannelEncryptRequest, ChannelEncryptResult, ClientEncryptResponse, DynMessage, NetMessage,
};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, WriteBytesExt};
use bytes::BytesMut;
use log::{debug, trace};
use protobuf::ProtobufEnum;
use std::convert::{TryFrom, TryInto};
use std::io::{Cursor, Write};
use steam_vent_crypto::{generate_session_key, symmetric_decrypt, symmetric_encrypt, CryptError};
use steam_vent_proto::enums_clientserver::EMsg;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};

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
}

pub type Result<T> = std::result::Result<T, NetworkError>;

pub async fn raw_connect<A: ToSocketAddrs>(addr: A) -> Result<(RawSteamReader, RawSteamWriter)> {
    let stream = TcpStream::connect(addr).await?;
    let (read, write) = stream.into_split();
    Ok((
        RawSteamReader {
            tcp: BufReader::new(read),
            buff: BytesMut::with_capacity(1024),
        },
        RawSteamWriter {
            tcp: BufWriter::new(write),
        },
    ))
}

const MAGIC: [u8; 4] = *b"VT01";

#[derive(Debug, Default, Copy, Clone, BinRead)]
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

#[derive(Debug)]
pub struct RawNetMessage<'a> {
    kind: EMsg,
    is_protobuf: bool,
    data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for RawNetMessage<'a> {
    type Error = NetworkError;

    fn try_from(value: &'a [u8]) -> Result<Self> {
        let kind = i32::from_le_bytes(
            value[0..4]
                .try_into()
                .map_err(|_| NetworkError::InvalidMessageKind(0))?,
        );

        let is_protobuf = kind < 0;

        let kind = match steam_vent_proto::enums_clientserver::EMsg::from_i32(kind.abs()) {
            Some(kind) => kind,
            None => return Err(NetworkError::InvalidMessageKind(kind)),
        };

        Ok(RawNetMessage {
            kind,
            is_protobuf,
            data: &value[4..],
        })
    }
}

pub struct RawSteamReader {
    tcp: BufReader<OwnedReadHalf>,
    buff: BytesMut,
}

impl RawSteamReader {
    async fn read_buff(&mut self) -> Result<&[u8]> {
        let mut header_bytes = [0; 8];
        self.tcp.read_exact(&mut header_bytes).await?;
        let header: Header = Cursor::new(&header_bytes[..]).read_le().unwrap();
        header.validate()?;
        debug!("got header for packet of {} bytes", header.length);

        self.buff.resize(header.length as usize, 0);
        self.tcp.read_exact(self.buff.as_mut()).await?;
        Ok(self.buff.as_ref())
    }

    pub async fn read<T: NetMessage>(&mut self) -> Result<T> {
        let raw = self.read_buff().await.and_then(RawNetMessage::try_from)?;
        if raw.kind == T::KIND {
            let mut reader = Cursor::new(raw.data);
            Ok(T::read_body(&mut reader)?)
        } else {
            Err(NetworkError::DifferentMessage(T::KIND, raw.kind))
        }
    }
}

pub struct RawSteamWriter {
    tcp: BufWriter<OwnedWriteHalf>,
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

pub struct SteamReader {
    raw: RawSteamReader,
    key: [u8; 32],
}

impl SteamReader {
    pub async fn read<T: NetMessage>(&mut self) -> Result<T> {
        let raw = self.raw.read_buff().await?;
        let decrypted = symmetric_decrypt(raw.to_vec(), &self.key)?;
        let raw = RawNetMessage::try_from(decrypted.as_slice())?;
        if raw.kind == T::KIND {
            let mut reader = Cursor::new(raw.data);
            Ok(T::read_body(&mut reader)?)
        } else {
            Err(NetworkError::DifferentMessage(T::KIND, raw.kind))
        }
    }
    pub async fn dyn_read(&mut self) -> Result<DynMessage> {
        let raw = self.raw.read_buff().await?;
        let decrypted = symmetric_decrypt(raw.to_vec(), &self.key)?;
        let raw = RawNetMessage::try_from(decrypted.as_slice())?;
        Ok(DynMessage {
            kind: raw.kind,
            body: raw.data.to_vec(),
        })
    }
}

pub struct SteamWriter {
    raw: RawSteamWriter,
    key: [u8; 32],
}

impl SteamWriter {
    pub async fn write<T: NetMessage>(&mut self, message: &T) -> Result<()> {
        debug!("sending {:?} message", T::KIND);
        trace!("  {:#?}", message);
        let message_size = message.encode_size().unwrap_or(128);
        let mut raw = Vec::with_capacity(4 + message_size);

        WriteBytesExt::write_i32::<LittleEndian>(&mut raw, T::KIND.value())?;
        message.write_body(&mut raw)?;

        // todo
        let raw = vec![
            138, 21, 0, 128, 29, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 160, 1, 16, 0, 81, 255, 255, 255,
            255, 255, 255, 255, 255, 89, 255, 255, 255, 255, 255, 255, 255, 255, 8, 172, 128, 4,
            24, 15, 50, 0, 56, 181, 254, 255, 255, 15, 64, 0, 90, 5, 13, 0, 0, 0, 0, 136, 2, 2,
            130, 5, 9, 97, 110, 111, 110, 121, 109, 111, 117, 115, 144, 5, 0, 248, 5, 0, 130, 6, 0,
            176, 6, 0,
        ];
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

pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<(SteamReader, SteamWriter)> {
    let (mut raw_reader, mut raw_writer) = raw_connect(addr).await?;

    let encrypt_request = raw_reader.read::<ChannelEncryptRequest>().await?;

    trace!("using nonce: {:?}", encrypt_request.nonce);
    let key = generate_session_key(None);

    trace!("generated session keys: {:?}", key.plain);
    trace!("  encrypted: {:?}", key.encrypted);

    let response = ClientEncryptResponse {
        target_job_id: u64::MAX,
        source_job_id: u64::MAX,
        protocol: encrypt_request.protocol,
        encrypted_key: key.encrypted,
    };
    raw_writer.write_message(&response).await?;

    let encrypt_response = raw_reader.read::<ChannelEncryptResult>().await?;

    if encrypt_response.result != 1 {
        return Err(NetworkError::CryptoHandshakeFailed);
    }

    debug!("crypt handshake complete");

    Ok((
        SteamReader {
            raw: raw_reader,
            key: key.plain,
        },
        SteamWriter {
            raw: raw_writer,
            key: key.plain,
        },
    ))
}
