use protobuf::Message;
use std::fmt::Debug;
use std::io::{Read, Write};
use steam_vent_proto::{RpcMessage, RpcMethod};

pub trait ServiceMethodRequest: Debug + Message {
    const REQ_NAME: &'static str;
    type Response: RpcMessage;

    fn parse(_reader: &mut dyn Read) -> protobuf::Result<Self>;
    fn write(&self, _writer: &mut dyn Write) -> protobuf::Result<()>;
    fn encode_size(&self) -> usize;
}

impl<T: RpcMethod> ServiceMethodRequest for T {
    const REQ_NAME: &'static str = T::METHOD_NAME;
    type Response = T::Response;

    fn parse(reader: &mut dyn Read) -> protobuf::Result<Self> {
        <Self as RpcMessage>::parse(reader)
    }

    fn write(&self, writer: &mut dyn Write) -> protobuf::Result<()> {
        <Self as RpcMessage>::write(self, writer)
    }

    fn encode_size(&self) -> usize {
        <Self as RpcMessage>::encode_size(&self)
    }
}
