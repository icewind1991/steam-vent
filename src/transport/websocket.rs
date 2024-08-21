use crate::message::flatten_multi;
use crate::net::{NetworkError, RawNetMessage};
use crate::transport::assert_can_unsplit;
use futures_util::{Sink, SinkExt, StreamExt, TryStreamExt};
use rustls::{ClientConfig, KeyLogFile, RootCertStore};
use std::future::ready;
use std::sync::Arc;
use tokio_stream::Stream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use tracing::{debug, instrument};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

#[instrument]
pub async fn connect(
    addr: &str,
) -> Result<(
    impl Stream<Item = Result<RawNetMessage>>,
    impl Sink<RawNetMessage, Error = NetworkError>,
)> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to setup crypto provider");
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
        flatten_multi(
            raw_read
                .map_err(NetworkError::from)
                .map_ok(|raw| raw.into_data())
                .map_ok(|vec| vec.into_iter().collect()) // this should be optimized to reuse the memory
                .map(|res| res.and_then(RawNetMessage::read)),
        ),
        raw_write.with(|msg: RawNetMessage| {
            let mut body = msg.header_buffer;
            assert_can_unsplit(&body, &msg.data);
            body.unsplit(msg.data);
            ready(Ok(WsMessage::binary(body)))
        }),
    ))
}
