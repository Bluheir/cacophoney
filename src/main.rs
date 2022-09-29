#![feature(let_chains)]

use aes_gcm::aead::Aead;
use aes_gcm::{aead::OsRng, Aes256Gcm};
use aes_gcm::{Key, KeyInit};

use futures::io::Cursor;
use rand::RngCore;
use std::{error::Error, time::Duration};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};
use ui::{ActionExecution, InputChangeReq, SelectOption};

use generic_array::GenericArray;

use crate::config::{Configuration, SecretConfiguration};
use crate::helpers::file::{encrypt, read_encrypted};
use crate::helpers::hash_s;

pub mod config;
pub mod data;
pub mod db;
pub mod helpers;
pub mod server;
pub mod ui;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // The main async tokio task sends data to the terminal
    let (s_send, t_recv) = mpsc::channel::<InputChangeReq>(1);
    // The terminal thread sends data to the main async tokio task
    let (t_send, s_recv) = mpsc::channel::<ActionExecution>(1);

    std::thread::spawn(move || {
        let _ = ui::terminal_init(t_send, t_recv);
    });

    let mut listener = TerminalListener {
        send: s_send,
        recv: s_recv,
    };

    // Wait until the terminal GUI is ready
    sleep(Duration::from_millis(10)).await;

    let config = get_config().await?;
    let secrets = File::open(&config.secret_config.location).await;

    let secrets = match secrets {
        Ok(mut f) => {
            log::debug!("Opening secrets file");

            let mut cipher = Vec::new();
            f.read_to_end(&mut cipher).await?;

            let nonce = get_nonce().await?;

            let mut dec_config = None;

            match config.secret_config.password {
                Some(p) => {
                    let h = hash_s(&p);
                    dec_config = read_encrypted::<SecretConfiguration>(&h, &nonce, &cipher)
                        .await
                        .ok();
                }
                // Config password is non-existant
                _ => {}
            }

            if dec_config.is_none() {
                // Start requesting the password
                for i in 0..4 {
                    let pass = listener
                        .pass_hash(
                            format!(
                                "Please type in the password to unlock the secrets file. ({}/4)",
                                i + 1
                            ),
                        )
                        .await?;

                    dec_config = read_encrypted(&pass, &nonce, &cipher).await.ok();

                    // Password is correct and the decrypted file is serialized
                    if dec_config.is_some() {
                        break;
                    }
                }
            }

            match dec_config {
                Some(mut secret) => {
                    match secret.private_key {
                        None => {
                            secret.private_key =
                                Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());
                        }
                        _ => {}
                    }

                    secret
                }
                None => {
                    log::warn!(
                        "Cannot decrypt secrets file. Generating a temporary random secret..."
                    );
                    // Generate a random secret
                    let mut secret = SecretConfiguration::default();
                    secret.private_key =
                        Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());

                    secret
                }
            }
        }
        Err(_) => {
            log::warn!("Secrets file doesn't exist");
            let r = listener
                .yes_or_no("Secrets file doesn't exist. Would you like to create one?".to_string())
                .await?;
            let mut secret = SecretConfiguration::default();

            let key1 = libsecp256k1::SecretKey::random(&mut OsRng).serialize();

            if !config.secret_config.restart_key {
                // Assign the private key
                secret.private_key = Some(key1);
            }

            if r == "Yes".to_string() {
                let mut f = File::create(&config.secret_config.location).await?;
                let pass = listener
                    .pass_hash(
                        "Please type in the password for the secrets file. Type empty for none."
                            .to_string(),
                    )
                    .await?;

                let s = serde_cbor::to_vec(&secret)?;

                // Get or generate the nonce
                let nonce = get_nonce().await?;

                // Encrypt
                let w = encrypt(&pass, &nonce, &secret).await?;

                f.write_all(&w).await?;
            }

            if config.secret_config.restart_key {
                secret.private_key = Some(key1);
            }

            secret
        }
    };

    if config.main_config.secure &&
        let Some(path) = config.main_config.cert_path &&
        let Some(private_path) = config.main_config.private_key_path {

        if let Ok(mut pubfile) = File::open(path).await &&
            let Ok(mut privfile) = File::open(private_path).await {

            let mut buf = Vec::new();
            let bufread = pubfile.read_buf(&mut buf).await;
        }
    }

    loop {}
}

async fn get_nonce() -> Result<[u8; 12], Box<dyn Error>> {
    let nonce = File::open("./secrets/nonce").await;

    let mut f = match nonce {
        Ok(f) => f,
        Err(_) => {
            log::info!("Creating nonce");
            let mut f = File::create("./secrets/nonce").await?;

            // Write a random nonce
            let mut n = [0u8; 12];
            OsRng::fill_bytes(&mut OsRng, &mut n);

            f.write_all(&n).await?;

            return Ok(n);
        }
    };

    let mut n = [0u8; 12];
    f.read_exact(&mut n).await?;

    Ok(n)
}

async fn get_config() -> Result<Configuration, Box<dyn Error>> {
    let config = File::open("./Config.toml").await;

    let mut f = match config {
        Ok(f) => f,
        Err(_) => {
            log::info!("Creating config file at location ./Config.toml");
            let mut f = File::create("./Config.toml").await?;

            // Write default config
            f.write_all(config::DEFAULT_CONFIG.as_bytes()).await?;

            f
        }
    };

    let mut v = String::new();
    f.read_to_string(&mut v).await?;

    Ok(toml::from_str::<Configuration>(&v)?)
}

/// Listens to messages from the terminal UI
pub struct TerminalListener {
    pub send: Sender<InputChangeReq>,
    pub recv: Receiver<ActionExecution>,
}

impl TerminalListener {
    /// Prompts the terminal to ask yes or no to the user and returns the response as a string
    pub async fn yes_or_no(&mut self, q: String) -> Result<String, Box<dyn Error>> {
        // Send the yes/no request
        self.send
            .send(InputChangeReq::Options(SelectOption {
                title: q,
                current: 0,
                options: vec!["Yes".to_string(), "No".to_string()],
            }))
            .await?;

        // Await the response
        let n = self.recv.recv().await.unwrap();

        match n {
            ActionExecution::Select(s) => return Ok(s),
            ActionExecution::Input(_) => panic!(), // Shouldn't end up here
        }
    }
    pub async fn password(&mut self, q: String) -> Result<String, Box<dyn Error>> {
        // Send the password request
        self.send
            .send(InputChangeReq::Input(q, ui::InputType::Password))
            .await?;

        let n = self.recv.recv().await.unwrap();

        match n {
            ActionExecution::Input(s) => return Ok(s),
            ActionExecution::Select(_) => panic!(), // Shouldn't end up here
        }
    }
    pub async fn pass_hash(&mut self, q: String) -> Result<[u8; 32], Box<dyn Error>> {
        let pass = self.password(q).await?;
        Ok(hash_s(&pass))
    }
    pub async fn pass_key(&mut self, q: String) -> Result<Key<Aes256Gcm>, Box<dyn Error>> {
        let pass1 = self.password(q).await?;
        let hash = blake3::hash(pass1.as_bytes());
        Ok(GenericArray::from_slice(hash.as_bytes()).clone())
    }
}
