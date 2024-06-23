use another_steam_totp::generate_auth_code;
use async_trait::async_trait;
use futures_util::future::{Either, select};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Stdin, stdin, Stdout, stdout};
use steam_vent_proto::steammessages_auth_steamclient::{CAuthentication_AllowedConfirmation, EAuthSessionGuardType};
use crate::auth::SteamGuardToken;
use tokio::io::AsyncBufReadExt;

#[derive(Debug, Clone)]
pub struct ConfirmationMethod(CAuthentication_AllowedConfirmation);

impl From<CAuthentication_AllowedConfirmation> for ConfirmationMethod {
    fn from(value: CAuthentication_AllowedConfirmation) -> Self {
        Self(value)
    }
}

impl ConfirmationMethod {
    pub fn confirmation_type(&self) -> &'static str {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => "unknown",
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => "none",
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => "email",
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => "device code",
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                "device confirmation"
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                "email confirmation"
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => "machine token",
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => "machine auth",
        }
    }

    pub fn confirmation_details(&self) -> &str {
        self.0.associated_message()
    }

    pub fn action_required(&self) -> bool {
        self.0.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
    }

    pub fn class(&self) -> ConfirmationMethodClass {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => ConfirmationMethodClass::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => ConfirmationMethodClass::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {
                ConfirmationMethodClass::Code
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                ConfirmationMethodClass::Code
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                ConfirmationMethodClass::Confirmation
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                ConfirmationMethodClass::Confirmation
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => {
                ConfirmationMethodClass::Stored
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => {
                ConfirmationMethodClass::Stored
            }
        }
    }

    pub fn guard_type(&self) -> GuardType {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => GuardType::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => GuardType::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => GuardType::Email,
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => GuardType::Device,
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => GuardType::Device,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => GuardType::Email,
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => GuardType::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => GuardType::None,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum ConfirmationMethodClass {
    Code,
    Confirmation,
    Stored,
    None,
}

#[derive(Debug)]
pub enum ConfirmationAction {
    GuardToken(SteamGuardToken, GuardType),
    None,
    Abort,
}

#[derive(Debug)]
pub enum GuardType {
    Email,
    Device,
    None,
}

impl From<GuardType> for EAuthSessionGuardType {
    fn from(value: GuardType) -> Self {
        match value {
            GuardType::Device => EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
            GuardType::Email => EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
            GuardType::None => EAuthSessionGuardType::k_EAuthSessionGuardType_None,
        }
    }
}

#[async_trait]
pub trait AuthConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction>;
}

pub type ConsoleAuthConfirmationHandler = UserProvidedAuthConfirmationHandler<Stdin, Stdout>;

pub struct UserProvidedAuthConfirmationHandler<Read, Write> {
    input: BufReader<Read>,
    output: Write,
}

pub struct SharedSecretAuthConfirmationHandler {
    shared_secret: String,
}

impl SharedSecretAuthConfirmationHandler {
    pub fn new(shared_secret: &str) -> Self {
        SharedSecretAuthConfirmationHandler {
            shared_secret: shared_secret.into(),
        }
    }
}

impl Default for ConsoleAuthConfirmationHandler {
    fn default() -> Self {
        ConsoleAuthConfirmationHandler {
            input: BufReader::new(stdin()),
            output: stdout(),
        }
    }
}

#[async_trait]
impl<Read, Write> AuthConfirmationHandler for UserProvidedAuthConfirmationHandler<Read, Write>
where
    Read: AsyncRead + Unpin + Send + Sync,
    Write: AsyncWrite + Unpin + Send + Sync,
{
    async fn handle_confirmation(
        mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Code {
                let msg = format!(
                    "{}: {}",
                    method.confirmation_type(),
                    method.confirmation_details()
                );
                self.output.write_all(msg.as_bytes()).await.ok();
                self.output.flush().await.ok();
                let mut buff = String::with_capacity(16);
                self.input.read_line(&mut buff).await.ok();
                buff.truncate(buff.trim().len());
                if buff.is_empty() {
                    return Some(ConfirmationAction::Abort);
                } else {
                    let token = SteamGuardToken(buff);
                    return Some(ConfirmationAction::GuardToken(token, method.guard_type()));
                }
            }
        }
        None
    }
}

#[async_trait]
impl AuthConfirmationHandler for SharedSecretAuthConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Code {
                let auth_code = generate_auth_code(self.shared_secret, None)
                    .expect("Could not generate auth code given shared secret.");
                let token = SteamGuardToken(auth_code);
                return Some(ConfirmationAction::GuardToken(token, method.guard_type()));
            }
        }
        None
    }
}

#[derive(Default)]
pub struct DeviceConfirmationHandler;

#[async_trait]
impl AuthConfirmationHandler for DeviceConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Confirmation {
                return Some(ConfirmationAction::None);
            }
        }
        None
    }
}

pub struct EitherConfirmationHandler<Left, Right> {
    left: Left,
    right: Right,
}

impl<Left, Right> EitherConfirmationHandler<Left, Right> {
    pub fn new(left: Left, right: Right) -> Self {
        Self { left, right }
    }
}

#[async_trait]
impl<Left, Right> AuthConfirmationHandler for EitherConfirmationHandler<Left, Right>
where
    Left: AuthConfirmationHandler + Send + Sync,
    Right: AuthConfirmationHandler + Send + Sync,
{
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        match select(
            self.left.handle_confirmation(allowed_confirmations),
            self.right.handle_confirmation(allowed_confirmations),
        )
            .await
        {
            Either::Left((left_result, right_fut)) => {
                if !matches!(left_result, None | Some(ConfirmationAction::None)) {
                    left_result
                } else {
                    right_fut.await
                }
            }
            Either::Right((right_result, left_fut)) => {
                if !matches!(right_result, None | Some(ConfirmationAction::None)) {
                    right_result
                } else {
                    left_fut.await
                }
            }
        }
    }
}