use std::env::args;
use std::error::Error;
use steam_vent::{
    auth::{
        AuthConfirmationHandler, AuthData, ConsoleAuthConfirmationHandler,
        DeviceConfirmationHandler, StartedAuth,
    },
    Connection, ServerList,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");

    let server_list = ServerList::discover().await?;
    let mut connection = Connection::connect(&server_list).await?;
    let auth =
        StartedAuth::begin_via_credentials(&connection, AuthData::new(&account, &password)).await?;
    let tokens = auth
        .wait_confirmation(
            &connection,
            ConsoleAuthConfirmationHandler::default().or(DeviceConfirmationHandler),
        )
        .await?;
    connection
        .login_with_token(&account, &tokens.refresh_token, auth.steam_id())
        .await?;

    // if necessary
    // connection.setup_heartbeat();

    println!("access token: {}", tokens.access_token);
    println!("refresh token: {}", tokens.refresh_token);

    Ok(())
}
