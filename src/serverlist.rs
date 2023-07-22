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

#[derive(Default, Clone, Debug)]
pub struct DiscoverOptions {
    web_client: Option<Client>,
    // todo: some smart cell based routing based on
    // https://raw.githubusercontent.com/SteamDatabase/SteamTracking/6d23ebb0070998ae851278cfae5f38832f4ac28d/ClientExtracted/steam/cached/CellMap.vdf
    cell: u8,
}

impl DiscoverOptions {
    pub fn with_web_client(self, web_client: Client) -> Self {
        DiscoverOptions {
            web_client: Some(web_client),
            ..self
        }
    }

    pub fn with_cell(self, cell: u8) -> Self {
        DiscoverOptions { cell, ..self }
    }
}

#[derive(Debug)]
pub struct ServerList {
    servers: Vec<SocketAddr>,
}

impl ServerList {
    pub async fn discover() -> Result<ServerList, ServerDiscoveryError> {
        Self::discover_with(DiscoverOptions::default()).await
    }

    pub async fn discover_with(
        options: DiscoverOptions,
    ) -> Result<ServerList, ServerDiscoveryError> {
        let client = options.web_client.unwrap_or_default();
        let cell = options.cell;

        let response: ServerListResponse = client
            .get(&format!(
                "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid={cell}"
            ))
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
