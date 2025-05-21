# Moved to https://codeberg.org/icewind/steam-vent

# Steam-Vent

### Interact with the Steam network via rust

Allows communication with the steam servers using the same protocol as the regular steam client.

## State

While the project is still incomplete, the most forms of authenticating to steam are implemented and you can send
requests for the protobuf definitions included in the project.

- [x] Anonymous sessions
- [x] Password Authentication
- [ ] QR Authentication
- [x] Steam guard (device or email) confirmation
- [x] Device notification confirmation
- [x] Saved machine token confirmation
- [x] Sending and receiving raw messages
- [x] Making RPC calls over the connection
- [x] Communicating with the game coordinator
- [ ] High level wrappers around the RPC calls
- [x] Allow using messages from protobufs not included in the project

## Usage

Note that this project is still in early development and apis might see large changes.

```rust
use std::error::Error;
use steam_vent::connection::Connection;
use steam_vent::proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;
use steam_vent::serverlist::ServerList;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_list = ServerList::discover().await?;
    let mut connection = Connection::anonymous(server_list).await?;

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
```

## Credit

This is in large parts inspired by and based of [@DoctorMcKay's](https://github.com/DoctorMcKay) work
on [SteamUser](https://github.com/DoctorMcKay/node-steam-user/),
massive credits go to all who worked on that.
