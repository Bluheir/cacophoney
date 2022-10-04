use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("deserialization of file failed")]
    DeserializeError(#[from] serde_cbor::Error),
    #[error("password decryption failed")]
    PasswordError(#[from] aes_gcm::Error),
    #[error("cannot read file")]
    IoError(#[from] tokio::io::Error)
}

#[derive(Error, Debug)]
pub enum ReadEncryptError {
    #[error("deserialization of file failed")]
    DeserializeError(#[from] serde_cbor::Error),
    #[error("password decryption failed")]
    PasswordError(#[from] aes_gcm::Error)
}

impl From<ReadEncryptError> for ConfigError {
    fn from(v : ReadEncryptError) -> ConfigError {
        match v {
            ReadEncryptError::DeserializeError(v) => ConfigError::DeserializeError(v),
            ReadEncryptError::PasswordError(v)    => ConfigError::PasswordError(v)
        }
    }
}