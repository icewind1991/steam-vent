use std::env::args;
use steam_vent::auth::{
    AuthConfirmationHandler, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler,
    FileGuardDataStore,
};
use steam_vent::proto::steammessages_player_steamclient::CPlayer_GetOwnedGames_Request;
use steam_vent::{Connection, ConnectionError, ConnectionTrait, ServerList};

#[tokio::main]
async fn main() -> Result<(), ConnectionError> {
    tracing_subscriber::fmt::init();

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
