use std::error::Error;
use steam_vent::{Connection, ServerList};
use steam_vent_proto::steammessages_clientserver_appinfo::{
    cmsg_client_picsproduct_info_request, CMsgClientPICSProductInfoRequest,
    CMsgClientPICSProductInfoResponse,
};

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

    let job_id = connection.send(msg).await?;
    println!(
        "response {:#?}",
        connection
            .receive_by_job_id::<CMsgClientPICSProductInfoResponse>(job_id)
            .await
    );

    Ok(())
}
