use crate::net::{NetMessageHeader, NetworkError, SteamReader, SteamWriter};
use crate::proto::steammessages_base::CMsgIPAddress;
use crate::proto::steammessages_clientserver_login::CMsgClientLogon;
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Network error: {0:#}")]
    Network(#[from] NetworkError),
}

pub struct Session {
    steam_id: SteamID,
}

pub type Result<T> = std::result::Result<T, SessionError>;

impl Session {
    pub async fn anonymous(read: &mut SteamReader, write: &mut SteamWriter) -> Result<Self> {
        Self::login(
            read,
            write,
            SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
        )
        .await
    }

    pub async fn login(
        read: &mut SteamReader,
        write: &mut SteamWriter,
        steam_id: SteamID,
    ) -> Result<Self> {
        let mut logon = CMsgClientLogon::new();
        logon.set_protocol_version(65580);
        logon.set_client_os_type(203);
        logon.set_anon_user_target_account_name(String::from("anonymous"));
        logon.set_should_remember_password(false);
        logon.set_supports_rate_limit_response(false);

        let mut ip = CMsgIPAddress::new();
        ip.set_v4(0);
        logon.set_obfuscated_private_ip(ip);
        logon.set_client_language(String::new());
        logon.set_machine_name(String::new());
        logon.set_steamguard_dont_remember_computer(false);
        logon.set_chat_mode(2);

        let header = NetMessageHeader {
            session_id: 0,
            source_job_id: u64::MAX,
            target_job_id: u64::MAX,
            steam_id,
        };

        write.write(&header, &logon).await?;
        Ok(Session { steam_id })
    }
}
