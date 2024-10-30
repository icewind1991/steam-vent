use rand::prelude::*;
use reqwest::{Client, Error};
use serde::Deserialize;
use std::iter::Cycle;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::vec::IntoIter;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerDiscoveryError {
    #[error("Failed send discovery request: {0:#}")]
    Network(reqwest::Error),
    #[error("steam returned an empty server list")]
    NoServers,
    #[error("steam returned an empty websocket server list")]
    NoWsServers,
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

#[derive(Debug, Clone)]
pub struct ServerList {
    servers: Arc<Mutex<Cycle<IntoIter<SocketAddr>>>>,
    ws_servers: Arc<Mutex<Cycle<IntoIter<String>>>>,
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
            .get(format!(
                "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid={cell}"
            ))
            .send()
            .await?
            .json()
            .await?;
        if response.response.server_list.is_empty() {
            return Err(ServerDiscoveryError::NoServers);
        }
        if response.response.server_list.is_empty() {
            return Err(ServerDiscoveryError::NoWsServers);
        }
        Ok(response.into())
    }

    /// Pick a server from the server list, rotating them in a round-robin way for reconnects.
    ///
    /// # Returns
    /// The selected `SocketAddr`
    pub fn pick(&self) -> SocketAddr {
        // SAFETY:
        // `lock` cannot panic as we cannot lock again within the same thread.
        // `unwrap` is safe as `discover_with` already checks for servers being present.
        let addr = self.servers.lock().unwrap().next().unwrap();
        debug!(addr = ?addr, "picked server from list");
        addr
    }

    /// Pick a WebSocket server from the server list, rotating them in a round-robin way for reconnects.
    ///
    /// # Returns
    /// A WebSocket URL to connect to, if the server list contains any servers.
    pub fn pick_ws(&self) -> String {
        // SAFETY: Same as for `pick`.
        let addr = self.ws_servers.lock().unwrap().next().unwrap();
        debug!(addr = ?addr, "picked websocket server from list");
        format!("wss://{addr}/cmsocket/")
    }
}

impl From<ServerListResponse> for ServerList {
    fn from(value: ServerListResponse) -> Self {
        let (mut servers, mut ws_servers) = (
            value.response.server_list,
            value.response.server_list_websockets,
        );
        servers.shuffle(&mut thread_rng());
        ws_servers.shuffle(&mut thread_rng());

        ServerList {
            servers: Arc::new(Mutex::new(servers.into_iter().cycle())),
            ws_servers: Arc::new(Mutex::new(ws_servers.into_iter().cycle())),
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
    #[serde(rename = "serverlist_websockets")]
    server_list_websockets: Vec<String>,
}
