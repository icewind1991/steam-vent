use std::error::Error;
use steam_vent::connection::Connection;
use steam_vent_proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut connection = Connection::anonymous().await?;

    let mut req = CGameServers_GetServerList_Request::new();
    req.set_limit(100);
    dbg!(connection.service_method(req).await)?;

    Ok(())
}
