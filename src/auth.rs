use crate::connection::Connection;
use crate::proto::enums::ESessionPersistence;
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_BeginAuthSessionViaCredentials_Request, EAuthTokenPlatformType,
};
use crate::session::{get_password_rsa, LoginError, Session, SessionError};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use protobuf::EnumOrUnknown;
use steam_vent_crypto::encrypt_with_key_pkcs1;
use tracing::info;

pub async fn password_auth(
    connection: &mut Connection,
    account: &str,
    password: &str,
) -> Result<Session, SessionError> {
    let (pub_key, timestamp) = get_password_rsa(connection, account.into()).await?;
    let encrypted_password =
        encrypt_with_key_pkcs1(&pub_key, password.as_bytes()).map_err(LoginError::InvalidPubKey)?;
    let encoded_password = BASE64_STANDARD.encode(encrypted_password);
    info!(account, "starting credentials login");
    dbg!(encoded_password.len(), password);
    let req = CAuthentication_BeginAuthSessionViaCredentials_Request {
        account_name: Some(account.into()),
        encrypted_password: Some(encoded_password),
        encryption_timestamp: Some(timestamp),

        // todo: platform types
        device_friendly_name: Some("DESKTOP-VENT".into()),
        platform_type: Some(EnumOrUnknown::new(
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
        )),
        persistence: Some(EnumOrUnknown::new(
            ESessionPersistence::k_ESessionPersistence_Persistent,
        )),
        website_id: Some("Client".into()),

        ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
    };
    dbg!(&req);
    let res = connection.service_method(req).await?;
    dbg!(res);
    todo!();
}

pub struct SteamGuardToken(String);
