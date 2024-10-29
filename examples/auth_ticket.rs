use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use futures_util::StreamExt;
use std::env::args;
use std::error::Error;
use steam_vent::auth::{
    AuthConfirmationHandler, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler,
    FileGuardDataStore,
};
use steam_vent::connection::{ReadonlyConnection, UnAuthenticatedConnection};
use steam_vent::ServerList;
use steam_vent_proto::steammessages_clientserver::CMsgClientGameConnectTokens;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");

    let server_list = ServerList::discover().await?;
    let connection = UnAuthenticatedConnection::connect(&server_list).await?;
    // listen for messages before starting the authentication because steam can send the tickets before
    // the login call returns
    let mut tokens_messages = connection.on::<CMsgClientGameConnectTokens>();

    let _connection = connection
        .login(
            &account,
            &password,
            FileGuardDataStore::user_cache(),
            ConsoleAuthConfirmationHandler::default().or(DeviceConfirmationHandler),
        )
        .await?;

    while let Some(Ok(tokens_message)) = tokens_messages.next().await {
        println!("got {} token from message", tokens_message.tokens.len());
        for token in tokens_message.tokens.into_iter() {
            println!("\t{}", BASE64_STANDARD.encode(token));
        }
    }
    Ok(())
}
