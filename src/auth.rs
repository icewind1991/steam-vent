use crate::connection::Connection;
use crate::message::MalformedBody;
use crate::message::NetMessage;
use crate::net::NetworkError;
use crate::proto::enums::ESessionPersistence;
use crate::proto::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_BeginAuthSessionViaCredentials_Request, CAuthentication_DeviceDetails,
    EAuthTokenPlatformType,
};
use crate::session::{login, LoginError, Session, SessionError};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use num_bigint_dig::BigUint;
use num_traits::Num;
use protobuf::{EnumOrUnknown, MessageField};
use rsa::RsaPublicKey;
use steam_vent_crypto::encrypt_with_key_pkcs1;
use tracing::{debug, info, instrument};

pub async fn password_auth(
    connection: &mut Connection,
    account: &str,
    password: &str,
) -> Result<Session, SessionError> {
    connection.session = login(connection, account).await?;
    let (pub_key, timestamp) = get_password_rsa(connection, account.into()).await?;
    let encrypted_password =
        encrypt_with_key_pkcs1(&pub_key, password.as_bytes()).map_err(LoginError::InvalidPubKey)?;
    let encoded_password = BASE64_STANDARD.encode(encrypted_password);
    info!(account, "starting credentials login");
    dbg!(encoded_password.len());
    let req = CAuthentication_BeginAuthSessionViaCredentials_Request {
        account_name: Some(account.into()),
        encrypted_password: Some(encoded_password),
        encryption_timestamp: Some(timestamp),

        // todo: platform types
        // device_friendly_name: Some("DESKTOP-VENT".into()),
        // platform_type: Some(EnumOrUnknown::new(
        //     EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
        // )),
        persistence: Some(EnumOrUnknown::new(
            ESessionPersistence::k_ESessionPersistence_Persistent,
        )),
        website_id: Some("Client".into()),

        device_details: MessageField::some(CAuthentication_DeviceDetails {
            device_friendly_name: Some("DESKTOP-VENT".into()),
            platform_type: Some(EnumOrUnknown::new(
                EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
            )),
            os_type: Some(1),
            ..CAuthentication_DeviceDetails::default()
        }),
        ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
    };
    dbg!(&req);
    let res = connection.service_method(req).await?;
    dbg!(res);
    todo!();
}

pub struct SteamGuardToken(String);

#[instrument(skip(connection))]
pub async fn get_password_rsa(
    connection: &mut Connection,
    account: String,
) -> Result<(RsaPublicKey, u64), NetworkError> {
    debug!("getting password rsa");
    let req = CAuthentication_GetPasswordRSAPublicKey_Request {
        account_name: Some(account),
        ..CAuthentication_GetPasswordRSAPublicKey_Request::default()
    };
    let response = connection.service_method(req).await?;

    let key_mod =
        BigUint::from_str_radix(response.publickey_mod.as_deref().unwrap_or_default(), 16)
            .map_err(|e| {
                MalformedBody::new(CAuthentication_GetPasswordRSAPublicKey_Request::KIND, e)
            })?;
    let key_exp =
        BigUint::from_str_radix(response.publickey_exp.as_deref().unwrap_or_default(), 16)
            .map_err(|e| {
                MalformedBody::new(CAuthentication_GetPasswordRSAPublicKey_Request::KIND, e)
            })?;
    let key = RsaPublicKey::new(key_mod, key_exp).map_err(|e| {
        MalformedBody::new(CAuthentication_GetPasswordRSAPublicKey_Request::KIND, e)
    })?;
    Ok((key, response.timestamp.unwrap_or_default()))
}
