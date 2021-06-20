use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use binread::BinRead;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crc::{Crc, CRC_32_ISO_HDLC};
use flate2::read::GzDecoder;
use log::{debug, trace};
use protobuf::{Message, ProtobufError};
use std::any::type_name;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::io::{Cursor, Read, Seek, Write};
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::steammessages_base::CMsgMulti;
use steam_vent_proto::steammessages_clientserver::CMsgClientServersAvailable;
use steam_vent_proto::steammessages_clientserver_login::{
    CMsgClientLogon, CMsgClientLogonResponse,
};
use thiserror::Error;

#[derive(Error, Debug)]
#[error("Malformed message body for {0:?}: {1}")]
pub struct MalformedBody(EMsg, MessageBodyError);

#[derive(Error, Debug)]
pub enum MessageBodyError {
    #[error("{0}")]
    Protobuf(#[from] ProtobufError),
    #[error("{0}")]
    BinRead(#[from] binread::Error),
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
    #[error("malformed child: {0}")]
    MalformedChild(Box<NetworkError>),
}

impl From<String> for MessageBodyError {
    fn from(e: String) -> Self {
        MessageBodyError::Other(e)
    }
}

#[derive(Error, Debug)]
pub enum DynMessageError {
    #[error("Difference message expected, expected {0:?}, got {1:?}")]
    InvalidMessageKind(EMsg, EMsg),
    #[error("{0}")]
    MalformedBody(#[from] crate::message::MalformedBody),
}

pub trait NetMessage: Sized + Debug {
    const KIND: EMsg;
    const IS_PROTOBUF: bool = false;

    fn read_body<R: Read + Seek>(_reader: &mut R) -> Result<Self, MalformedBody> {
        panic!("Reading not implemented for {}", type_name::<Self>())
    }

    fn write_body<W: Write>(&self, _writer: &mut W) -> Result<(), std::io::Error> {
        panic!("Writing not implemented for {}", type_name::<Self>())
    }

    fn encode_size(&self) -> Option<usize> {
        None
    }
}

#[derive(Debug)]
pub struct DynMessage {
    pub kind: EMsg,
    pub body: Vec<u8>,
}

impl DynMessage {
    pub fn try_into<T: NetMessage>(self) -> Result<T, DynMessageError> {
        if self.kind == T::KIND {
            Ok(T::read_body(&mut Cursor::new(self.body))?)
        } else {
            Err(DynMessageError::InvalidMessageKind(T::KIND, self.kind))
        }
    }
}

#[derive(Debug, BinRead)]
pub struct ChannelEncryptRequest {
    pub protocol: u32,
    pub universe: u32,
    pub nonce: [u8; 16],
}

impl NetMessage for ChannelEncryptRequest {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptRequest;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        trace!("reading body of {:?} message", Self::KIND);
        ChannelEncryptRequest::read(reader).map_err(|e| MalformedBody(Self::KIND, e.into()))
    }
}

#[derive(Debug, BinRead)]
pub struct ChannelEncryptResult {
    pub result: u32,
}

impl NetMessage for ChannelEncryptResult {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptResult;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        trace!("reading body of {:?} message", Self::KIND);
        ChannelEncryptResult::read(reader).map_err(|e| MalformedBody(Self::KIND, e.into()))
    }
}

#[derive(Debug)]
pub struct ClientEncryptResponse {
    pub protocol: u32,
    pub encrypted_key: Vec<u8>,
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

impl NetMessage for ClientEncryptResponse {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptResponse;

    fn write_body<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        trace!("writing body of {:?} message", Self::KIND);
        writer.write_u64::<LittleEndian>(u64::MAX)?;
        writer.write_u64::<LittleEndian>(u64::MAX)?;
        writer.write_u32::<LittleEndian>(self.protocol)?;
        writer.write_u32::<LittleEndian>(self.encrypted_key.len() as u32)?;
        writer.write_all(&self.encrypted_key)?;

        let mut digest = CRC.digest();
        digest.update(&self.encrypted_key);
        writer.write_u32::<LittleEndian>(digest.finalize())?;
        writer.write_u32::<LittleEndian>(0)?;
        Ok(())
    }

    fn encode_size(&self) -> Option<usize> {
        Some(8 + 8 + 4 + 4 + self.encrypted_key.len() + 4 + 4)
    }
}

#[derive(Debug)]
pub struct Multi {
    pub messages: Vec<(NetMessageHeader, DynMessage)>,
}

enum MaybeZipReader {
    Raw(Cursor<Vec<u8>>),
    Zipped(GzDecoder<Cursor<Vec<u8>>>),
}

impl Read for MaybeZipReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            MaybeZipReader::Raw(raw) => raw.read(buf),
            MaybeZipReader::Zipped(zipped) => zipped.read(buf),
        }
    }
}

impl NetMessage for Multi {
    const KIND: EMsg = EMsg::k_EMsgMulti;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        trace!("reading body of {:?} message", Self::KIND);
        Ok(Multi {
            messages: Self::iter(reader)?
                .collect::<Result<Vec<_>, NetworkError>>()
                .map_err(|e| {
                    MalformedBody(Self::KIND, MessageBodyError::MalformedChild(Box::new(e)))
                })?,
        })
    }
}

impl Multi {
    pub fn iter<R: Read + Seek>(
        reader: &mut R,
    ) -> Result<
        impl Iterator<Item = Result<(NetMessageHeader, DynMessage), NetworkError>>,
        MalformedBody,
    > {
        MultiBodyIter::new(reader)
    }
}

struct MultiBodyIter<R> {
    reader: R,
}

impl MultiBodyIter<MaybeZipReader> {
    pub fn new<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        let mut multi = CMsgMulti::parse_from_reader(reader)
            .map_err(|e| MalformedBody(EMsg::k_EMsgMulti, e.into()))?;

        let data = match multi.get_size_unzipped() {
            0 => MaybeZipReader::Raw(Cursor::new(multi.take_message_body())),
            _ => MaybeZipReader::Zipped(GzDecoder::new(Cursor::new(multi.take_message_body()))),
        };

        Ok(MultiBodyIter { reader: data })
    }
}

impl<R: Read> Iterator for MultiBodyIter<R> {
    type Item = Result<(NetMessageHeader, DynMessage), NetworkError>;

    fn next(&mut self) -> Option<Self::Item> {
        let size = match self.reader.read_u32::<LittleEndian>() {
            Ok(size) => size,
            Err(_) => return None,
        };

        let mut msg_data = Vec::with_capacity(size as usize);
        msg_data.resize(size as usize, 0);
        if let Err(e) = self.reader.read_exact(&mut msg_data) {
            return Some(Err(NetworkError::IO(e)));
        }
        let raw = match RawNetMessage::try_from(msg_data.as_slice()) {
            Ok(raw) => raw,
            Err(e) => return Some(Err(e)),
        };

        debug!("Reading child message {:?}", raw.kind);

        Some(Ok((
            raw.header,
            DynMessage {
                kind: raw.kind,
                body: raw.data.to_vec(),
            },
        )))
    }
}

macro_rules! proto_msg {
    ($kind:expr => $ty:ident) => {
        impl NetMessage for $ty {
            const KIND: EMsg = $kind;
            const IS_PROTOBUF: bool = true;

            fn write_body<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
                trace!("writing body of protobuf message {:?}", Self::KIND);
                self.write_to_writer(writer)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
            }

            fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
                trace!("reading body of protobuf message {:?}", Self::KIND);
                $ty::parse_from_reader(reader).map_err(|e| MalformedBody(Self::KIND, e.into()))
            }
        }
    };
}

proto_msg!(EMsg::k_EMsgClientLogon => CMsgClientLogon);
proto_msg!(EMsg::k_EMsgClientLogOnResponse => CMsgClientLogonResponse);
proto_msg!(EMsg::k_EMsgClientServersAvailable => CMsgClientServersAvailable);
