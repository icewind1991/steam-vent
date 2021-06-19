use std::error::Error;
use steam_vent::message::Multi;
use steam_vent::net::connect;
use steam_vent_proto::steammessages_base::CMsgIPAddress;
use steam_vent_proto::steammessages_clientserver_login::CMsgClientLogon;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let (mut read, mut write) = connect("155.133.248.39:27020").await?;

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
    logon.set_steamguard_dont_remember_computer(false);
    logon.set_chat_mode(2);

    write.write(&logon).await.unwrap();

    let (_header, res) = read.read::<Multi>().await?;
    println!(
        "Got expected multi with {} sub messages",
        res.messages.len()
    );
    for sub_message in res.messages {
        dbg!(sub_message.kind);
    }

    Ok(())
}
