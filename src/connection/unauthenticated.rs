use super::raw::RawConnection;
use super::Result;
use crate::auth::{begin_password_auth, AuthConfirmationHandler, GuardDataStore};
use crate::message::{ServiceMethodMessage, ServiceMethodResponseMessage};
use crate::net::RawNetMessage;
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, login};
use crate::{Connection, ConnectionError, NetworkError, ServerList};
use futures_util::future::{select, Either};
use std::pin::pin;
use steam_vent_proto::enums_clientserver::EMsg;
use steamid_ng::{AccountType, SteamID};
use tokio::time::timeout;
use tracing::{debug, error};

pub struct UnAuthenticatedConnection(RawConnection);

impl UnAuthenticatedConnection {
    pub async fn connect(server_list: &ServerList) -> Result<Self, ConnectionError> {
        Ok(UnAuthenticatedConnection(
            RawConnection::connect(server_list).await?,
        ))
    }

    pub async fn anonymous(self) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        raw.session = anonymous(&raw, AccountType::AnonUser).await?;
        raw.setup_heartbeat();
        let connection = Connection::new(raw);

        Ok(connection)
    }

    pub async fn anonymous_server(self) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        raw.session = anonymous(&raw, AccountType::AnonGameServer).await?;
        raw.setup_heartbeat();
        let connection = Connection::new(raw);

        Ok(connection)
    }

    pub async fn login<H: AuthConfirmationHandler, G: GuardDataStore>(
        self,
        account: &str,
        password: &str,
        mut guard_data_store: G,
        confirmation_handler: H,
    ) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        let guard_data = guard_data_store.load(account).await.unwrap_or_else(|e| {
            error!(error = ?e, "failed to retrieve guard data");
            None
        });
        if guard_data.is_some() {
            debug!(account, "found stored guard data");
        }
        let begin = begin_password_auth(&mut raw, account, password, guard_data.as_deref()).await?;
        let steam_id = SteamID::from(begin.steam_id());

        let allowed_confirmations = begin.allowed_confirmations();

        let tokens = match select(
            pin!(confirmation_handler.handle_confirmation(&allowed_confirmations)),
            pin!(begin.poll().wait_for_tokens(&raw)),
        )
        .await
        {
            Either::Left((confirmation_action, tokens_fut)) => {
                if let Some(confirmation_action) = confirmation_action {
                    begin.submit_confirmation(&raw, confirmation_action).await?;
                    tokens_fut.await?
                } else if begin.action_required() {
                    return Err(ConnectionError::UnsupportedConfirmationAction(
                        allowed_confirmations.clone(),
                    ));
                } else {
                    tokens_fut.await?
                }
            }
            Either::Right((tokens, _)) => tokens?,
        };

        if let Some(guard_data) = tokens.new_guard_data {
            if let Err(e) = guard_data_store.store(account, guard_data).await {
                error!(error = ?e, "failed to store guard data");
            }
        }

        raw.session = login(
            &mut raw,
            account,
            steam_id,
            // yes we send the refresh token as access token, yes it makes no sense, yes this is actually required
            tokens.refresh_token.as_ref(),
        )
        .await?;
        raw.setup_heartbeat();
        let connection = Connection::new(raw);

        Ok(connection)
    }
}

pub(crate) async fn service_method_un_authenticated<Msg: ServiceMethodRequest>(
    connection: &RawConnection,
    msg: Msg,
) -> Result<Msg::Response> {
    let header = connection.session.header(true);
    let recv = connection.filter.on_job_id(header.source_job_id);
    let msg = RawNetMessage::from_message_with_kind(
        header,
        ServiceMethodMessage(msg),
        EMsg::k_EMsgServiceMethodCallFromClientNonAuthed,
        true,
    )?;
    connection.sender.send_raw(msg).await?;
    let message = timeout(connection.timeout, recv)
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(|_| NetworkError::Timeout)?
        .into_message::<ServiceMethodResponseMessage>()?;
    message.into_response::<Msg>()
}
