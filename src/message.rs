use binread::BinRead;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::GzDecoder;
use protobuf::ProtobufEnum;
use protobuf::{parse_from_reader, Message};
use std::any::type_name;
use std::io::{Cursor, Read, Seek, Write};
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::steammessages_base::CMsgMulti;
use steam_vent_proto::steammessages_clientserver::CMsgClientServersAvailable;
use steam_vent_proto::steammessages_clientserver_login::{
    CMsgClientLogon, CMsgClientLogonResponse,
};
use thiserror::Error;

#[derive(Error, Debug)]
#[error("Malformed message body for {0:?}")]
pub struct MalformedBody(EMsg);

#[derive(Error, Debug)]
pub enum DynMessageError {
    #[error("Difference message expected, expected {0:?}, got {1:?}")]
    InvalidMessageKind(EMsg, EMsg),
    #[error("{0}")]
    MalformedBody(#[from] crate::message::MalformedBody),
}

pub trait NetMessage: Sized {
    const KIND: EMsg;

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

pub struct DynMessage {
    pub kind: EMsg,
    pub body: Vec<u8>,
}

impl DynMessage {
    fn try_into<T: NetMessage>(self) -> Result<T, DynMessageError> {
        if self.kind == T::KIND {
            Ok(T::read_body(&mut Cursor::new(self.body))?)
        } else {
            Err(DynMessageError::InvalidMessageKind(T::KIND, self.kind))
        }
    }
}

#[derive(Debug, BinRead)]
pub struct ChannelEncryptRequest {
    pub target_job_id: u64,
    pub source_job_id: u64,
    pub protocol: u32,
    pub universe: u32,
    pub nonce: [u8; 16],
}

impl NetMessage for ChannelEncryptRequest {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptRequest;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        ChannelEncryptRequest::read(reader).map_err(|_| MalformedBody(Self::KIND))
    }
}

#[derive(Debug, BinRead)]
pub struct ChannelEncryptResult {
    pub target_job_id: u64,
    pub source_job_id: u64,
    pub result: u32,
}

impl NetMessage for ChannelEncryptResult {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptResult;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        ChannelEncryptResult::read(reader).map_err(|_| MalformedBody(Self::KIND))
    }
}

#[derive(Debug)]
pub struct ClientEncryptResponse {
    pub target_job_id: u64,
    pub source_job_id: u64,
    pub protocol: u32,
    pub encrypted_key: Vec<u8>,
}

impl NetMessage for ClientEncryptResponse {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptResponse;

    fn write_body<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        writer.write_u64::<LittleEndian>(self.target_job_id)?;
        writer.write_u64::<LittleEndian>(self.source_job_id)?;
        writer.write_u32::<LittleEndian>(self.protocol)?;
        writer.write_u32::<LittleEndian>(self.encrypted_key.len() as u32)?;
        writer.write_all(&self.encrypted_key)?;
        writer.write_u32::<LittleEndian>(crc::crc32::checksum_ieee(&self.encrypted_key))?;
        writer.write_u32::<LittleEndian>(0)?;
        Ok(())
    }

    fn encode_size(&self) -> Option<usize> {
        Some(8 + 8 + 4 + 4 + self.encrypted_key.len() + 4 + 4)
    }
}

pub struct Multi {
    messages: Vec<DynMessage>,
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
        Ok(Multi {
            messages: Self::iter(reader)?.collect::<Result<Vec<_>, MalformedBody>>()?,
        })
    }
}

impl Multi {
    fn iter<R: Read + Seek>(
        reader: &mut R,
    ) -> Result<impl Iterator<Item = Result<DynMessage, MalformedBody>>, MalformedBody> {
        let mut multi =
            parse_from_reader::<CMsgMulti>(reader).map_err(|_| MalformedBody(Self::KIND))?;

        let data = match multi.get_size_unzipped() {
            0 => MaybeZipReader::Raw(Cursor::new(multi.take_message_body())),
            _ => MaybeZipReader::Zipped(GzDecoder::new(Cursor::new(multi.take_message_body()))),
        };

        Ok(MultiBodyIter { reader: data })
    }
}

struct MultiBodyIter<R> {
    reader: R,
}

impl<R: Read> Iterator for MultiBodyIter<R> {
    type Item = Result<DynMessage, MalformedBody>;

    fn next(&mut self) -> Option<Self::Item> {
        let size = match self.reader.read_u32::<LittleEndian>() {
            Ok(size) => size,
            Err(_) => return None,
        };

        let kind = match self.reader.read_i32::<LittleEndian>() {
            Ok(kind) => kind,
            Err(_) => return Some(Err(MalformedBody(Multi::KIND))),
        };

        let kind = match steam_vent_proto::enums_clientserver::EMsg::from_i32(kind.abs()) {
            Some(kind) => kind,
            None => return Some(Err(MalformedBody(Multi::KIND))),
        };
        let mut msg_data = Vec::with_capacity(size as usize);
        msg_data.resize(size as usize, 0);
        if let Err(_) = self.reader.read_exact(&mut msg_data) {
            return Some(Err(MalformedBody(Multi::KIND)));
        }

        Some(Ok(DynMessage {
            kind,
            body: msg_data,
        }))
    }
}

macro_rules! proto_msg {
    ($kind:expr => $ty:ident) => {
        impl NetMessage for $ty {
            const KIND: EMsg = $kind;

            fn write_body<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
                self.write_to_writer(writer)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
            }

            fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
                parse_from_reader(reader).map_err(|_| MalformedBody(Self::KIND))
            }
        }
    };
}

proto_msg!(EMsg::k_EMsgClientLogonGameServer => CMsgClientLogon);
proto_msg!(EMsg::k_EMsgClientLogOnResponse => CMsgClientLogonResponse);
proto_msg!(EMsg::k_EMsgClientServersAvailable => CMsgClientServersAvailable);
