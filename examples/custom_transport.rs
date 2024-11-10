use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use rustls::{ClientConfig, KeyLogFile, RootCertStore};
use std::error::Error;
use std::future::ready;
use std::sync::Arc;
use steam_vent::connection::UnAuthenticatedConnection;
use steam_vent::{NetworkError, ServerList};
use tokio_tungstenite::tungstenite::{Message as WsMessage, Message};
use tokio_tungstenite::{connect_async_tls_with_config, Connector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let server_list = ServerList::discover().await?;
    let (sender, receiver) = connect(&server_list.pick_ws()).await?;
    let connection = UnAuthenticatedConnection::from_sender_receiver(sender, receiver).await?;
    let _connection = connection.anonymous().await?;

    Ok(())
}

// this is just a copy of the standard websocket transport implementation, functioning as an example
// how to implement a websocket transport
pub async fn connect(
    addr: &str,
) -> Result<
    (
        impl Sink<BytesMut, Error = NetworkError>,
        impl Stream<Item = Result<BytesMut, NetworkError>>,
    ),
    NetworkError,
> {
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
