use crate::message::flatten_multi;
use crate::net::{NetworkError, RawNetMessage};
use futures_sink::Sink;
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use std::future::ready;
use tokio_stream::Stream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, instrument};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

#[instrument]
pub async fn connect(
    addr: &str,
) -> Result<(
    impl Stream<Item = Result<RawNetMessage>>,
    impl Sink<RawNetMessage, Error = NetworkError>,
)> {
    let (stream, _) = connect_async(addr).await?;
    debug!("connected to websocket server");
    let (raw_write, raw_read) = stream.split();

    Ok((
        flatten_multi(
            raw_read
                .map_err(NetworkError::from)
                .map_ok(|raw| raw.into_data())
                .map_ok(|vec| vec.into_iter().collect()) // this should be optimized to reuse the memory
                .map(|res| res.and_then(RawNetMessage::read)),
        ),
        raw_write.with(|msg: RawNetMessage| {
            let mut body = Vec::with_capacity(msg.header_buffer.len() + msg.data.len());
            body.extend_from_slice(msg.header_buffer.as_ref());
            body.extend_from_slice(msg.data.as_ref());
            ready(Ok(WsMessage::binary(body)))
        }),
    ))
}
