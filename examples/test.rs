use steam_vent::proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;
use steam_vent::{Connection, ConnectionError, ServerList};

#[tokio::main]
async fn main() -> Result<(), ConnectionError> {
    tracing_subscriber::fmt::init();

    let server_list = ServerList::discover().await?;
    let connection = Connection::anonymous(server_list).await?;

    println!("requesting servers");

    let mut req = CGameServers_GetServerList_Request::new();
    req.set_limit(16);
    req.set_filter(r"\appid\440".into());
    let some_tf2_servers = connection.service_method(req).await?;
    for server in some_tf2_servers.servers {
        println!(
            "{}({}) playing {}",
            server.name(),
            server.addr(),
            server.map()
        );
    }

    Ok(())
}
