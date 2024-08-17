mod generated;

pub use generated::enums_clientserver::EMsg;
pub use generated::*;

pub use protobuf;
use std::fmt::Debug;
use std::io::{Read, Write};

/// Constant used to verify that all proto crates use the same version of the codegen.
pub const VERSION_0_5_0: () = ();

pub trait RpcService {
    const SERVICE_NAME: &'static str;
}

pub trait RpcMethod: protobuf::Message + RpcMessage {
    const METHOD_NAME: &'static str;
    type Response: RpcMessage;
}

pub trait RpcMessage: Debug + Sized {
    fn parse(_reader: &mut dyn Read) -> protobuf::Result<Self>;

    fn write(&self, _writer: &mut dyn Write) -> protobuf::Result<()>;

    fn encode_size(&self) -> usize;
}

impl RpcMessage for () {
    fn parse(_reader: &mut dyn Read) -> protobuf::Result<Self> {
        Ok(())
    }

    fn write(&self, _writer: &mut dyn Write) -> protobuf::Result<()> {
        Ok(())
    }

    fn encode_size(&self) -> usize {
        0
    }
}

pub trait RpcMessageWithKind: RpcMessage {
    const KIND: EMsg;
}
