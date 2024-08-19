use std::error::Error;
use steam_vent::proto::steammessages_clientserver_appinfo::{
    cmsg_client_picsproduct_info_request, CMsgClientPICSProductInfoRequest,
    CMsgClientPICSProductInfoResponse,
};
use steam_vent::{Connection, ServerList};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let server_list = ServerList::discover().await?;
    let connection = Connection::anonymous(server_list).await?;

    let msg = CMsgClientPICSProductInfoRequest {
        apps: vec![cmsg_client_picsproduct_info_request::AppInfo {
            appid: Some(440),
            only_public_obsolete: Some(true),
            ..Default::default()
        }],
        meta_data_only: Some(true),
        single_response: Some(true),
        ..Default::default()
    };

    let response: CMsgClientPICSProductInfoResponse = connection.job(msg).await?;
    println!("response {:#?}", response);

    Ok(())
}
