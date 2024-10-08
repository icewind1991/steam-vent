use std::env::args;
use std::error::Error;
use std::io::stdin;
use steam_vent::auth::{
    AuthConfirmationHandler, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler,
    FileGuardDataStore,
};
use steam_vent::proto::steammessages_friendmessages_steamclient::{
    CFriendMessages_IncomingMessage_Notification, CFriendMessages_SendMessage_Request,
};
use steam_vent::{Connection, ConnectionTrait, ServerList};
use steam_vent_proto::enums::EPersonaStateFlag;
use steam_vent_proto::steammessages_clientserver_friends::CMsgClientChangeStatus;
use steamid_ng::SteamID;
use tokio::spawn;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");
    let target_steam_id = SteamID::try_from(args.next().expect("no target steam id").as_str())
        .expect("invalid steam id");

    let server_list = ServerList::discover().await?;
    let connection = Connection::login(
        &server_list,
        &account,
        &password,
        FileGuardDataStore::user_cache(),
        ConsoleAuthConfirmationHandler::default().or(DeviceConfirmationHandler),
    )
    .await?;

    connection
        .send(CMsgClientChangeStatus {
            persona_state: Some(1),
            persona_state_flags: Some(
                EPersonaStateFlag::k_EPersonaStateFlag_ClientTypeMobile as u32,
            ),
            ..Default::default()
        })
        .await?;

    let mut incoming_messages =
        connection.on_notification::<CFriendMessages_IncomingMessage_Notification>();
    spawn(async move {
        while let Some(Ok(incoming)) = incoming_messages.next().await {
            println!("{}: {}", incoming.steamid_friend(), incoming.message());
        }
    });
    let mut read_buff = String::with_capacity(32);
    loop {
        read_buff.clear();
        stdin().read_line(&mut read_buff).expect("stdin error");
        let input = read_buff.trim();
        if !input.is_empty() {
            let req = CFriendMessages_SendMessage_Request {
                steamid: Some(target_steam_id.into()),
                message: Some(input.into()),
                chat_entry_type: Some(1),
                ..CFriendMessages_SendMessage_Request::default()
            };
            connection.service_method(req).await?;
        }
    }
}
