use crate::message::{
    flatten_multi, ChannelEncryptRequest, ChannelEncryptResult, ClientEncryptResponse, NetMessage,
};
use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::transport::assert_can_unsplit;
use bytemuck::{cast, Pod, Zeroable};
use bytes::{Buf, BufMut, BytesMut};
use futures_util::future::ready;
use futures_util::{Sink, SinkExt, StreamExt, TryStreamExt};
use std::convert::TryInto;
use std::fmt::Debug;
use steam_vent_crypto::{
    generate_session_key, symmetric_decrypt, symmetric_encrypt_with_iv_buffer,
};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_stream::Stream;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::{debug, instrument, trace};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

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
) -> Result<(), NetworkError> {
    let mut buff = BytesMut::with_capacity(message.encode_size() + 4);

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
