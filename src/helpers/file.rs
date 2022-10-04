use std::error::Error;

use aes_gcm::{
    aead::{Aead},
    Aes256Gcm, KeyInit,
};
use generic_array::GenericArray;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, AsyncReadExt},
};

use crate::error::ReadEncryptError;

pub async fn get_toml<T: DeserializeOwned>(
    path: &str,
    default: &'static str,
) -> Result<T, Box<dyn Error>> {
    let config = File::open(path).await;

    let mut f = match config {
        Ok(f) => f,
        Err(_) => {
            tracing::info!("Creating TOML file at location {}", path);
            let mut f = File::create(path).await?;

            // Write default config
            f.write_all(default.as_bytes()).await?;

            let obj = toml::from_str::<T>(default)?;
            return Ok(obj);
        }
    };

    let mut v = String::new();
    f.read_to_string(&mut v).await?;

    Ok(toml::from_str::<T>(&v)?)
}

pub async fn read_encrypted<T: DeserializeOwned>(
    pass: &[u8; 32],
    nonce: &[u8; 12],
    cipher: &[u8],
) -> Result<T, ReadEncryptError> {
    let pass = GenericArray::from_slice(pass);
    let nonce = GenericArray::from_slice(nonce);

    let d = Aes256Gcm::new(pass);

    let dec = d.decrypt(nonce, cipher)?;
    Ok(serde_cbor::from_slice(&dec)?)
}
pub async fn encrypt<T: Serialize>(
    pass: &[u8; 32],
    nonce: &[u8; 12],
    data: &T,
) -> Vec<u8> {
    let pass = GenericArray::from_slice(pass);
    let nonce = GenericArray::from_slice(nonce);

    let d = Aes256Gcm::new(pass);
    let p = serde_cbor::to_vec(data).unwrap();

    d.encrypt(nonce, &*p).unwrap()
}
