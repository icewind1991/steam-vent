use std::env::args;
use std::error::Error;
use steam_vent::auth::ConsoleAuthConfirmationHandler;
use steam_vent::connection::Connection;
use steam_vent::proto::steammessages_player_steamclient::CPlayer_GetOwnedGames_Request;
use steam_vent::serverlist::ServerList;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");

    let server_list = ServerList::discover().await?;
    let mut connection = Connection::login(
        server_list,
        &account,
        &password,
        ConsoleAuthConfirmationHandler::default(),
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
