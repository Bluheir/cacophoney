use aes_gcm::aead::OsRng;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tokio::sync::mpsc::{self, Receiver, Sender, error::SendError};
use tokio::{runtime::Runtime, fs::File, io::{AsyncWriteExt, AsyncReadExt}};
use ui::{AppState, render_loop, InputChangeReq, ActionExecution, SelectOption};
use std::{error::Error, io, time::Duration};
use tui::{
    backend::{Backend, CrosstermBackend}, Terminal,
};
use tokio::time::sleep;

use crate::config::{Configuration, SecretConfiguration};

pub mod data;
pub mod db;
pub mod helpers;
pub mod server;
pub mod config;
pub mod ui;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>>{
    // The main async tokio task sends data to the terminal
    let (s_send, t_recv) = mpsc::channel::<InputChangeReq>(1);
    // The terminal thread sends data to the main async tokio task
    let (t_send, s_recv) = mpsc::channel::<ActionExecution>(1);

    std::thread::spawn(move || {
        let _ = ui::terminal_init(t_send, t_recv);
    });

    let mut listener = TerminalListener {
        send : s_send,
        recv : s_recv
    };

    // Wait until the terminal GUI is ready
    sleep(Duration::from_millis(10)).await;

    let config = get_config().await?;
    let secrets = File::open(&config.secret_config.location).await;

    let mut f = match secrets {
        Ok(f) => {
            
        },
        Err(_) => {
            log::warn!("Secrets file doesn't exist");
            let r = listener.yes_or_no("Secrets file doesn't exist. Would you like to create one?".to_string()).await?;
            let mut secret = SecretConfiguration::default();
            
            let key = libsecp256k1::SecretKey::random(&mut OsRng).serialize();

            if !config.secret_config.restart_key {
                // Assign the private key
                secret.private_key = Some(key);
            }

            if r == "Yes".to_string() {
                let f = File::create(&config.secret_config.location).await?;
                
                let s = serde_cbor::to_vec(&secret);
                //let encrypted = aes_gcm::Aes256Gcm;
            }
            else {

            }
        }
    };

    Ok(())
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

/// Listens to messages from the temrinal UI
pub struct TerminalListener {
    pub send : Sender<InputChangeReq>,
    pub recv : Receiver<ActionExecution>
}

impl TerminalListener {
    /// Prompts the terminal to ask yes or no to the user and returns the response as a string
    pub async fn yes_or_no(&mut self, q : String) -> Result<String, Box<dyn Error>> {
        // Send the yes/no request
        self.send.send(InputChangeReq::Options(SelectOption { 
            title: q, 
            current: 0, 
            options:  vec![
                "Yes".to_string(),
                "No".to_string()
            ]
        })).await?;

        // Await the response
        let n = self.recv.recv().await.unwrap();

        match n {
            ActionExecution::Select(s) => return Ok(s),
            ActionExecution::Input(_) => panic!(), // Shouldn't end up here
        }
    }
    pub async fn password(&mut self, q : String) -> Result<String, Box<dyn Error>> {
        // Send the password request
        self.send.send(InputChangeReq::Input(q)).await?;

        let n = self.recv.recv().await.unwrap();

        match n {
            ActionExecution::Input(s) => return Ok(s),
            ActionExecution::Select(_) => panic!(), // Shouldn't end up here
        }
    }
}