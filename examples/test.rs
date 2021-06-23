use std::error::Error;
use steam_vent::message::Multi;
use steam_vent::net::{connect, NetMessageHeader};
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::steammessages_base::CMsgIPAddress;
use steam_vent_proto::steammessages_clientserver_login::{
    CMsgClientLogon, CMsgClientLogonResponse,
};
use steamid_ng::{AccountType, Instance, SteamID, Universe};
use tokio::pin;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let (read, mut write) = connect("155.133.248.39:27020").await?;

    println!("Handshake done");

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
        steam_id: SteamID::new(0, Instance::All, AccountType::AnonUser, Universe::Public),
    };

    write.write(&header, &logon).await.unwrap();

    pin!(read);
    while let Some(result) = read.next().await {
        let msg = result?;
        match msg.kind {
            EMsg::k_EMsgClientLogOnResponse => {
                let (_, logon) = msg.read::<CMsgClientLogonResponse>()?;
                dbg!(logon);
            }
            _ => {
                dbg!(msg.kind);
            }
        }
    }

    Ok(())
}
