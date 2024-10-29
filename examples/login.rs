use std::env::args;
use std::error::Error;
use steam_vent::auth::{
    AuthConfirmationHandler, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler,
    FileGuardDataStore, SharedSecretAuthConfirmationHandler,
};
use steam_vent::proto::steammessages_player_steamclient::CPlayer_GetOwnedGames_Request;
use steam_vent::{Connection, ConnectionTrait, ServerList};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");
    // base64 encoded
    let guard_secret = args.next();

    let server_list = ServerList::discover().await?;
    let connection = match guard_secret {
        Some(secret) => {
            Connection::login(
                &server_list,
                &account,
                &password,
                FileGuardDataStore::user_cache(),
                SharedSecretAuthConfirmationHandler::new(&secret),
            )
            .await?
        }
        None => {
            Connection::login(
                &server_list,
                &account,
                &password,
                FileGuardDataStore::user_cache(),
                ConsoleAuthConfirmationHandler::default().or(DeviceConfirmationHandler),
            )
            .await?
        }
    };

    println!("requesting games");

    let req = CPlayer_GetOwnedGames_Request {
        steamid: Some(connection.steam_id().into()),
        include_appinfo: Some(true),
        include_played_free_games: Some(true),
        ..CPlayer_GetOwnedGames_Request::default()
    };
    let games = connection.service_method(req).await?;
    println!(
        "{} owns {} games",
        connection.steam_id().steam3(),
        games.game_count()
    );
    for game in games.games {
        println!(
            "{}: {} {}",
            game.appid(),
            game.name(),
            game.playtime_forever()
        );
    }

    Ok(())
}
