use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use futures_util::StreamExt;
use std::env::args;
use std::error::Error;
use steam_vent::auth::{
    AuthConfirmationHandler, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler,
    FileGuardDataStore,
};
use steam_vent::{Connection, ConnectionTrait, ServerList};
use steam_vent_proto::steammessages_clientserver::CMsgClientGameConnectTokens;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");

    let server_list = ServerList::discover().await?;

    let connection = Connection::login(
        &server_list,
        &account,
        &password,
        FileGuardDataStore::user_cache(),
        ConsoleAuthConfirmationHandler::default().or(DeviceConfirmationHandler),
    )
    .await?;

    let tokens_messages = connection.on::<CMsgClientGameConnectTokens>();

    // also process the messages that were received before we registered our filter
    let old_token_messages = connection
        .take_unprocessed()
        .into_iter()
        .filter_map(|raw| raw.into_message::<CMsgClientGameConnectTokens>().ok())
        .map(Ok);
    let mut tokens_messages = futures_util::stream::iter(old_token_messages).chain(tokens_messages);

    while let Some(Ok(tokens_message)) = tokens_messages.next().await {
        println!("got {} token from message", tokens_message.tokens.len());
        for token in tokens_message.tokens.into_iter() {
            println!("\t{}", BASE64_STANDARD.encode(token));
        }
    }
    Ok(())
}
