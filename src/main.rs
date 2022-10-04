#![feature(let_chains)]

use aes_gcm::aead::OsRng;
use config::{ConfigManager, SecretConfiguration};
use error::ConfigError;
use server::start_empty;
use tokio::io::AsyncReadExt;
use std::io::Write;
use std::sync::Arc;
use std::{error::Error, time::Duration};
use tokio::time::sleep;
use tokio::{
    fs::File,
    io::{AsyncWriteExt},
};
use rpassword::read_password;

use crate::config::{Configuration};

pub mod config;
pub mod data;
pub mod db;
pub mod error;
pub mod helpers;
pub mod server;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let (config, mgr) = ConfigManager::get_config("./Config.toml").await?;

    let pass = match &config.secret_config.password {
        Some(v) => v.clone(),
        None => {
            tracing::info!("Please type the password for the secrets file.");
            read_password().unwrap()
        }
    };

    let secret = match mgr.get_secrets(&pass).await {
        Ok(v) => {
            Some(v)
        }
        Err(e) => {
            match e {
                ConfigError::DeserializeError(v) => {
                    // There shouldn't be errors deserializing
                    panic!("{}", v)
                }
                ConfigError::IoError(_) => {
                    Some(mgr.create_secrets(&pass).await?)
                }
                ConfigError::PasswordError(_) => {
                    None                
                }
            }
        }
    };

    let secret = match secret {
        Some(v) => v,
        None => {
            let mut val = None;

            for i in 1..5 {
                tracing::info!("Please type the password for the secrets file. {}/5", i + 1);
                let password = read_password().unwrap();

                val = Some(mgr.get_secrets(&password).await?);

                if val.is_some() {
                    break;
                }
            }

            match val {
                Some(v) => v,
                None => { 
                    let mut v = SecretConfiguration::default();
                    v.private_key = Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());
                    v
                }
            }
        }
    };

    // Feature Checks
    let features = &config.main_config.features;


    // if features.contains("base") {
    //     tracing::info!("Starting base node...");

    //     let c = config.clone();

    //     tokio::spawn(async move {
    //         start_empty(c, server_config).await;
    //     });
    // }

    loop {}
}