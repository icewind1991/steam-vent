use crate::net::NetworkError;
use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, StreamExt, TryStreamExt};
use rustls::{ClientConfig, KeyLogFile, RootCertStore};
use std::future::ready;
use std::sync::Arc;
use tokio_stream::Stream;
use tokio_tungstenite::tungstenite::{Message as WsMessage, Message};
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use tracing::{debug, instrument};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

#[instrument]
pub async fn connect(
    addr: &str,
) -> Result<(
    impl Sink<BytesMut, Error = NetworkError>,
    impl Stream<Item = Result<BytesMut>>,
)> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // can only be once called
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.key_log = Arc::new(KeyLogFile::new());
    let tls_config = Connector::Rustls(Arc::new(tls_config));
    let (stream, _) = connect_async_tls_with_config(addr, None, false, Some(tls_config)).await?;
    debug!("connected to websocket server");
    let (raw_write, raw_read) = stream.split();

    Ok((
        raw_write.with(|msg: BytesMut| ready(Ok(WsMessage::binary(msg)))),
        raw_read
            .map_err(NetworkError::from)
            .map_ok(Message::into_data)
            .map_ok(Bytes::from)
            .map_ok(BytesMut::from),
    ))
}
