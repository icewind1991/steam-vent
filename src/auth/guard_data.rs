use directories::ProjectDirs;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fs::{create_dir_all, read_to_string, write};
use std::path::PathBuf;
use thiserror::Error;

/// Trait for storing steam guard machine tokens
pub trait GuardDataStore {
    type Err: Error;

    /// Store a machine token for an account
    fn store(
        &mut self,
        account: &str,
        machine_token: String,
    ) -> impl std::future::Future<Output = Result<(), Self::Err>> + Send;

    /// Retrieve the stored token for an account
    fn load(
        &mut self,
        account: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>, Self::Err>> + Send;
}

/// Error while storing or loading guard data from json file
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FileStoreError {
    /// Error while reading the json file
    #[error("error while reading tokens from {}: {:#}", path.display(), err)]
    Read { err: std::io::Error, path: PathBuf },
    /// Error while writing the json file
    #[error("error while writing tokens to {}: {:#}", path.display(), err)]
    Write { err: std::io::Error, path: PathBuf },
    /// Error when encoding or decoding the tokens
    #[error("error while parsing tokens from {}: {:#}", path.display(), err)]
    Json {
        err: serde_json::error::Error,
        path: PathBuf,
    },
    /// Error while creating the parent directory of the file
    #[error("error while directory {} for tokens: {:#}", path.display(), err)]
    DirCreation { err: std::io::Error, path: PathBuf },
}

/// Store the steam guard data in a json file
pub struct FileGuardDataStore {
    path: PathBuf,
}

impl FileGuardDataStore {
    /// Store the machine token at the provided path
    pub fn new(path: PathBuf) -> Self {
        FileGuardDataStore { path }
    }

    /// Store the machine tokens in the user's cache directory
    ///
    /// This will be
    /// - `$XDG_CACHE_HOME/steam-vent/machine_token.json` (where `$XDG_CACHE_HOME` defaults to `$HOME/.cache`) on Linux
    /// - `$HOME/Library/Caches/steam-vent/nl.icewind.steam-vent/machine_token.json` on macOS
    /// - `%LocalAppData%/icewind/steam-vent/cache/machine_token.json` on Windows
    pub fn user_cache() -> Self {
        let project_dirs = ProjectDirs::from("nl", "icewind", "steam-vent")
            .expect("user cache not supported on this platform");
        Self::new(project_dirs.cache_dir().join("machine_tokens.json"))
    }

    fn all_tokens(&self) -> Result<HashMap<String, String>, FileStoreError> {
        if !self.path.exists() {
            return Ok(HashMap::default());
        }
        let raw = read_to_string(&self.path).map_err(|err| FileStoreError::Read {
            err,
            path: self.path.clone(),
        })?;
        serde_json::from_str(&raw).map_err(|err| FileStoreError::Json {
            err,
            path: self.path.clone(),
        })
    }

    fn save(&self, tokens: HashMap<String, String>) -> Result<(), FileStoreError> {
        if let Some(parent) = self.path.parent() {
            create_dir_all(parent).map_err(|err| FileStoreError::DirCreation {
                err,
                path: parent.into(),
            })?;
        }

        let raw = serde_json::to_string(&tokens).map_err(|err| FileStoreError::Json {
            err,
            path: self.path.clone(),
        })?;
        write(&self.path, raw).map_err(|err| FileStoreError::Write {
            err,
            path: self.path.clone(),
        })?;
        Ok(())
    }
}

impl GuardDataStore for FileGuardDataStore {
    type Err = FileStoreError;

    async fn store(&mut self, account: &str, machine_token: String) -> Result<(), Self::Err> {
        if !machine_token.is_empty() {
            let mut tokens = self.all_tokens()?;
            tokens.insert(account.into(), machine_token);
            self.save(tokens)
        } else {
            Ok(())
        }
    }

    async fn load(&mut self, account: &str) -> Result<Option<String>, Self::Err> {
        let mut tokens = self.all_tokens()?;
        Ok(tokens.remove(account).filter(|token| !token.is_empty()))
    }
}

/// Don't store guard data
pub struct NullGuardDataStore;

impl GuardDataStore for NullGuardDataStore {
    type Err = Infallible;

    async fn store(&mut self, _account: &str, _machine_token: String) -> Result<(), Self::Err> {
        Ok(())
    }

    async fn load(&mut self, _account: &str) -> Result<Option<String>, Self::Err> {
        Ok(None)
    }
}
