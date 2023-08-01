# Steam-Vent

### Interact with the Steam network via rust

Allows communication with the steam servers using the same protocol as the regular steam client.

## State

While the project is still very incomplete, the basics of authenticating to steam and sending requests is working.

- [x] Anonymous sessions
- [x] Password Authentication
- [ ] QR Authentication
- [x] Steam guard (device or email) confirmation
- [ ] Device notification confirmation
- [ ] Saved machine token confirmation
- [x] Making RPC calls over the connection
- [ ] Support for all available RPC messages
- [ ] High level wrappers around the RPC calls 

## Usage

Note that this project is still in early development and api's might see large changes.

```rust
use std::error::Error;
use steam_vent::connection::Connection;
use steam_vent_proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut connection = Connection::anonymous().await?;

    let mut req = CGameServers_GetServerList_Request::new();
    req.set_limit(16);
    req.set_filter("\\appid\\440".into());
    let some_tf2_servers = connection.service_method(req).await?;
    for server in some_tf2_servers.servers {
        println!(
            "{}({}) playing {}",
            server.get_name(),
            server.get_addr(),
            server.get_map()
        );
    }

    Ok(())
}
```

## Credit

This is in large parts inspired by and based of [@DoctorMcKay's](https://github.com/DoctorMcKay) work on [SteamUser](https://github.com/DoctorMcKay/node-steam-user/),
massive credits go to all who worked on that. 