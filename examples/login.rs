use std::env::args;
use std::error::Error;
use steam_vent::connection::Connection;
use steam_vent::proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;
use steam_vent::serverlist::ServerList;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");

    let server_list = ServerList::discover().await?;
    let mut connection = Connection::login(server_list, &account, &password).await?;

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
