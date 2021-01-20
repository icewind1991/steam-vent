use std::error::Error;
use steam_vent::net::connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (_read, _write) = connect("155.133.248.39:27020").await?;

    println!("Handshake done");

    Ok(())
}
