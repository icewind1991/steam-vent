use binread::BinRead;
use std::io::{Read, Seek};
use steam_vent_proto::enums_clientserver::EMsg;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("Malformed message body for {0:?}")]
pub struct MalformedBody(EMsg);

pub trait NetMessage: Sized {
    const KIND: EMsg;

    fn try_read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody>;
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

    fn try_read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
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

    fn try_read_body<R: Read + Seek>(reader: &mut R) -> Result<Self, MalformedBody> {
        ChannelEncryptResultBody::read(reader).map_err(|_| MalformedBody(Self::KIND))
    }
}
