use std::error::Error;
use steam_vent::proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;
use steam_vent::{Connection, ConnectionTrait, ServerList};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let server_list = ServerList::discover().await?;
    let connection = Connection::anonymous(&server_list).await?;

    println!("requesting servers");

    let mut req = CGameServers_GetServerList_Request::new();
    req.set_limit(16);
    req.set_filter(r"\appid\440".into());
    let some_tf2_servers = connection.service_method(req).await?;
    for server in some_tf2_servers.servers {
        println!(
            "{}({}) playing {}",
            String::from_utf8_lossy(server.name()),
            server.addr(),
            server.map()
        );
    }

    Ok(())
}
