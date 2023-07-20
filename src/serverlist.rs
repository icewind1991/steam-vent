use reqwest::{Client, Error};
use serde::Deserialize;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerDiscoveryError {
    #[error("Failed send discovery request: {0:#}")]
    Network(reqwest::Error),
    #[error("steam returned an empty server list")]
    NoServers,
}

impl From<reqwest::Error> for ServerDiscoveryError {
    fn from(value: Error) -> Self {
        ServerDiscoveryError::Network(value)
    }
}

#[derive(Debug)]
pub struct ServerList {
    servers: Vec<SocketAddr>,
}

impl ServerList {
    pub async fn discover() -> Result<ServerList, ServerDiscoveryError> {
        // todo: some smart cell based routing based on
        // https://raw.githubusercontent.com/SteamDatabase/SteamTracking/6d23ebb0070998ae851278cfae5f38832f4ac28d/ClientExtracted/steam/cached/CellMap.vdf
        // or something
        let response: ServerListResponse = Client::new()
            .get("https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=15")
            .send()
            .await?
            .json()
            .await?;
        if response.response.server_list.is_empty() {
            return Err(ServerDiscoveryError::NoServers);
        }
        Ok(response.into())
    }

    pub fn pick(&self) -> SocketAddr {
        // todo: something more smart than always using the first
        *self.servers.first().unwrap()
    }
}

impl From<ServerListResponse> for ServerList {
    fn from(value: ServerListResponse) -> Self {
        ServerList {
            servers: value.response.server_list,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ServerListResponse {
    response: ServerListResponseInner,
}

#[derive(Debug, Deserialize)]
struct ServerListResponseInner {
    #[serde(rename = "serverlist")]
    server_list: Vec<SocketAddr>,
}
