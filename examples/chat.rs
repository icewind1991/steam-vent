use std::env::args;
use std::io::stdin;
use steam_vent::auth::ConsoleAuthConfirmationHandler;
use steam_vent::{Connection, ConnectionError, ServerList};
use steam_vent_proto::steammessages_friendmessages_steamclient::{
    CFriendMessages_IncomingMessage_Notification, CFriendMessages_SendMessage_Request,
};
use steamid_ng::SteamID;
use tokio::spawn;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), ConnectionError> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");
    let target_steam_id = SteamID::try_from(args.next().expect("no target steam id").as_str())
        .expect("invalid steam id");

    let server_list = ServerList::discover().await?;
    let connection = Connection::login(
        server_list,
        &account,
        &password,
        ConsoleAuthConfirmationHandler::default(),
    )
    .await?;

    let mut incoming_messages = connection.on::<CFriendMessages_IncomingMessage_Notification>();
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
