use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fs::{create_dir_all, read_to_string, write};
use std::path::PathBuf;
use async_trait::async_trait;
use directories::ProjectDirs;
use thiserror::Error;

#[async_trait]
pub trait GuardDataStore {
    type Err: Error;

    async fn store(&mut self, account: &str, machine_token: String) -> Result<(), Self::Err>;

    async fn load(&mut self, account: &str) -> Result<Option<String>, Self::Err>;
}

#[derive(Debug, Error)]
pub enum FileStoreError {
    #[error("error while reading tokens from {}: {:#}", path.display(), err)]
    Read { err: std::io::Error, path: PathBuf },
    #[error("error while writing tokens to {}: {:#}", path.display(), err)]
    Write { err: std::io::Error, path: PathBuf },
    #[error("error while parsing tokens from {}: {:#}", path.display(), err)]
    Json {
        err: serde_json::error::Error,
        path: PathBuf,
    },
    #[error("error while directory {} for tokens: {:#}", path.display(), err)]
    DirCreation { err: std::io::Error, path: PathBuf },
}

/// Store the steam guard data in a json file
pub struct FileGuardDataStore {
    path: PathBuf,
}

impl FileGuardDataStore {
    pub fn new(path: PathBuf) -> Self {
        FileGuardDataStore { path }
    }

    /// Store the machine tokens in the user's cache directory
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

#[async_trait]
impl crate::auth::GuardDataStore for FileGuardDataStore {
    type Err = FileStoreError;

    async fn store(&mut self, account: &str, machine_token: String) -> Result<(), Self::Err> {
        let mut tokens = self.all_tokens()?;
        tokens.insert(account.into(), machine_token);
        self.save(tokens)
    }

    async fn load(&mut self, account: &str) -> Result<Option<String>, Self::Err> {
        let mut tokens = self.all_tokens()?;
        Ok(tokens.remove(account))
    }
}

/// Don't store guard data
pub struct NullGuardDataStore;

#[async_trait]
impl crate::auth::GuardDataStore for NullGuardDataStore {
    type Err = Infallible;

    async fn store(&mut self, _account: &str, _machine_token: String) -> Result<(), Self::Err> {
        Ok(())
    }

    async fn load(&mut self, _account: &str) -> Result<Option<String>, Self::Err> {
        Ok(None)
    }
}