use std::error::Error;
use steam_vent::message::flatten_multi;
use steam_vent::net::connect;
use steam_vent::session::anonymous;
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::steammessages_clientserver_login::CMsgClientLoggedOff;
use steam_vent_proto::steammessages_gameservers_steamclient::CGameServers_GetServerIPsBySteamID_Request;
use tokio::pin;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let (read, mut write) = connect("155.133.248.39:27020").await?;
    let read = flatten_multi(read);
    pin!(read);

    let session = anonymous(&mut read, &mut write).await?;

    println!("Handshake done");

    let mut req = CGameServers_GetServerIPsBySteamID_Request::new();
    req.set_server_steamids(vec![76561198062247888]);
    session.send(&mut write, req).await?;

    while let Some(result) = read.next().await {
        let msg = result?;
        match msg.kind {
            EMsg::k_EMsgClientLoggedOff => {
                dbg!(msg.into_message::<CMsgClientLoggedOff>()?);
            }
            _ => {
                dbg!(msg.kind);
            }
        }
    }

    Ok(())
}
