use crate::auth::SteamGuardToken;
use another_steam_totp::generate_auth_code;
use futures_util::future::{select, Either};
use std::pin::pin;
use steam_vent_proto::steammessages_auth_steamclient::{
    CAuthentication_AllowedConfirmation, EAuthSessionGuardType,
};
use tokio::io::AsyncBufReadExt;
use tokio::io::{stdin, stdout, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Stdin, Stdout};

/// A method that can be used to confirm a login
#[derive(Debug, Clone)]
pub struct ConfirmationMethod(CAuthentication_AllowedConfirmation);

impl From<CAuthentication_AllowedConfirmation> for ConfirmationMethod {
    fn from(value: CAuthentication_AllowedConfirmation) -> Self {
        Self(value)
    }
}

impl ConfirmationMethod {
    /// Get the human-readable confirmation type
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

    /// Get the server-provided message for the confirmation
    pub fn confirmation_details(&self) -> &str {
        self.0.associated_message()
    }

    /// Is any action required to confirm the login
    pub fn action_required(&self) -> bool {
        self.0.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
    }

    /// Get the class of the confirmation
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

    /// Get the token type required for the confirmation, if the confirmation asks for a code
    pub fn token_type(&self) -> Option<GuardTokenType> {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => Some(GuardTokenType::Email),
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                Some(GuardTokenType::Device)
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => None,
        }
    }
}

/// The class of confirmation method
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum ConfirmationMethodClass {
    /// Provide a totp token
    Code,
    /// Confirm the login out-of-band
    Confirmation,
    /// Provide stored guard data
    Stored,
    /// No action required
    None,
}

/// The action to perform to confirm the login
#[non_exhaustive]
#[derive(Debug)]
pub enum ConfirmationAction {
    /// A totp token to send to the server
    GuardToken(SteamGuardToken, GuardTokenType),
    /// No action required
    None,
    /// Login has been canceled by the user
    Abort,
}

/// The type of guard token
#[derive(Debug)]
pub enum GuardTokenType {
    Email,
    Device,
}

impl From<GuardTokenType> for EAuthSessionGuardType {
    fn from(value: GuardTokenType) -> Self {
        match value {
            GuardTokenType::Device => EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
            GuardTokenType::Email => EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
        }
    }
}

/// A trait for handling login confirmations
///
/// The library comes with handlers for:
///
/// - Asking for a code from the terminal: [`ConsoleAuthConfirmationHandler`].
/// - Generating a code from the pre-shared secret: [`SharedSecretAuthConfirmationHandler`].
/// - Waiting for the user to confirm the login from the mobile app: [`DeviceConfirmationHandler`].
///
/// Additionally, apps can implement the trait to integrate the confirmation flow into the app.
pub trait AuthConfirmationHandler: Sized {
    /// Perform the confirmation action given a list of allowed confirmations for the login
    ///
    /// If the confirmation handler supports any of the allowed confirmations,
    /// it returns a [`ConfirmationAction`] with the required action.
    ///
    /// If the confirmation handler does not support any of the allowed confirmations it returns `None`.
    /// If no confirmation handler supports the allowed confirmations the login will fail.
    fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> impl std::future::Future<Output = Option<ConfirmationAction>> + Send;

    /// Return a new confirmation handler that combines the current one with a new one.
    ///
    /// The resulting confirmation handler will handle both handler in parallel.
    fn or<Right: AuthConfirmationHandler>(
        self,
        other: Right,
    ) -> EitherConfirmationHandler<Self, Right> {
        EitherConfirmationHandler::new(self, other)
    }
}

/// Ask the user for the totp token from the terminal
pub type ConsoleAuthConfirmationHandler = UserProvidedAuthConfirmationHandler<Stdin, Stdout>;

/// Ask the user to provide the totp token
pub struct UserProvidedAuthConfirmationHandler<Read, Write> {
    input: BufReader<Read>,
    output: Write,
}

impl Default for ConsoleAuthConfirmationHandler {
    fn default() -> Self {
        ConsoleAuthConfirmationHandler {
            input: BufReader::new(stdin()),
            output: stdout(),
        }
    }
}

impl<Read, Write> UserProvidedAuthConfirmationHandler<Read, Write>
where
    Read: AsyncRead + Unpin + Send + Sync,
    Write: AsyncWrite + Unpin + Send + Sync,
{
    /// Create an confirmation handling using the provided I/O
    ///
    /// The handler will write details about the required tokens to the output
    /// and expect the newline terminated token from the input
    pub fn new(input: Read, output: Write) -> Self {
        UserProvidedAuthConfirmationHandler {
            input: BufReader::new(input),
            output,
        }
    }
}

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
            if let Some(token_type) = method.token_type() {
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
                return if buff.is_empty() {
                    Some(ConfirmationAction::Abort)
                } else {
                    let token = SteamGuardToken(buff);
                    Some(ConfirmationAction::GuardToken(token, token_type))
                };
            }
        }
        None
    }
}

/// Generate the steam guard totp token from the shared secret
///
/// This requires no user interaction during login but requires the user to retrieve the totp secret in advance
pub struct SharedSecretAuthConfirmationHandler {
    shared_secret: String,
}

impl SharedSecretAuthConfirmationHandler {
    /// The totp shared secret encoded as base64
    ///
    /// Note that the secret as found in `totp://` urls is base32 encoded, not base64
    pub fn new(shared_secret: &str) -> Self {
        SharedSecretAuthConfirmationHandler {
            shared_secret: shared_secret.into(),
        }
    }
}

impl AuthConfirmationHandler for SharedSecretAuthConfirmationHandler {
    async fn handle_confirmation(
        self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Option<ConfirmationAction> {
        for method in allowed_confirmations {
            if let Some(token_type) = method.token_type() {
                let auth_code = generate_auth_code(self.shared_secret, None)
                    .expect("Could not generate auth code given shared secret.");
                let token = SteamGuardToken(auth_code);
                return Some(ConfirmationAction::GuardToken(token, token_type));
            }
        }
        None
    }
}

/// Wait for the user to confirm the login in the mobile app
#[derive(Default)]
pub struct DeviceConfirmationHandler;

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

/// Use multiple confirmation handlers in parallel.
///
/// This is primarily usefully for allowing users to pick between providing a totp code or confirming
/// the login in the mobile app.
pub struct EitherConfirmationHandler<Left, Right> {
    left: Left,
    right: Right,
}

impl<Left, Right> EitherConfirmationHandler<Left, Right> {
    pub fn new(left: Left, right: Right) -> Self {
        Self { left, right }
    }
}

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
            pin!(self.left.handle_confirmation(allowed_confirmations)),
            pin!(self.right.handle_confirmation(allowed_confirmations)),
        )
        .await
        {
            Either::Left((left_result, right_fut)) => match left_result {
                None | Some(ConfirmationAction::None) => right_fut.await,
                _ => left_result,
            },
            Either::Right((right_result, left_fut)) => match right_result {
                None | Some(ConfirmationAction::None) => left_fut.await,
                _ => right_result,
            },
        }
    }
}
