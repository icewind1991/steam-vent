use binread::BinRead;
use byteorder::{LittleEndian, WriteBytesExt};
use std::any::type_name;
use std::io::{Read, Seek, Write};
use steam_vent_proto::enums_clientserver::EMsg;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("Malformed message body for {0:?}")]
pub struct MalformedBody(EMsg);

pub trait NetMessage: Sized {
    const KIND: EMsg;

    fn read_body<R: Read + Seek>(_reader: &mut R) -> Result<Self, MalformedBody> {
        panic!("Reading not implemented for {}", type_name::<Self>())
    }

    fn write_body<W: Write>(&self, _writer: &mut W) -> Result<(), std::io::Error> {
        panic!("Writing not implemented for {}", type_name::<Self>())
    }

    fn encode_size(&self) -> usize {
        panic!("Writing not implemented for {}", type_name::<Self>())
    }
}

#[derive(Debug, BinRead)]
pub struct ChannelEncryptRequestBody {
    pub target_job_id: u64,
    pub source_job_id: u64,
    pub protocol: u32,
    pub universe: u32,
    pub nonce: [u8; 16],
}

impl NetMessage for ChannelEncryptRequestBody {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptRequest;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        ChannelEncryptRequestBody::read(reader).map_err(|_| MalformedBody(Self::KIND))
    }
}

#[derive(Debug, BinRead)]
pub struct ChannelEncryptResultBody {
    pub target_job_id: u64,
    pub source_job_id: u64,
    pub result: u32,
}

impl NetMessage for ChannelEncryptResultBody {
    const KIND: EMsg = EMsg::k_EMsgChannelEncryptResult;

    fn read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        ChannelEncryptResultBody::read(reader).map_err(|_| MalformedBody(Self::KIND))
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

    fn encode_size(&self) -> usize {
        8 + 8 + 4 + 4 + self.encrypted_key.len() + 4 + 4
    }
}
