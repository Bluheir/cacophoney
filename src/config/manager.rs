use futures::Future;
use rand::{rngs::OsRng, RngCore};
use rustls::{Certificate, PrivateKey};
use std::{collections::HashSet, error::Error, io::Cursor, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{error::{ConfigError}, helpers::hash_s, config};

use super::{Configuration, SecretConfiguration};

/// A manager for a configuration file. Can create secret configuration files.
pub struct ConfigManager {
    config: Arc<Configuration>,
}

impl ConfigManager {
    pub fn new(config: Arc<Configuration>) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &Configuration {
        &self.config
    }

    pub async fn get_config(path : &str) -> Result<(Arc<Configuration>, ConfigManager), Box<dyn Error>> {
        let config = File::open(path).await;
    
        let mut f = match config {
            Ok(f) => f,
            Err(_) => {
                tracing::info!("Creating config file at location {}", path);
                let mut f = File::create(path).await?;
    
                // Write default config
                f.write_all(config::DEFAULT_CONFIG.as_bytes()).await?;

                let arc = Arc::new(config::Configuration::default());
    
                return Ok((arc.clone(), Self::new(arc)));
            }
        };
    
        let mut v = String::new();
        f.read_to_string(&mut v).await?;
    
        let arc = Arc::new(toml::from_str::<Configuration>(&v)?);

        Ok((arc.clone(), Self::new(arc)))
    }

    pub async fn get_nonce(&self) -> Result<[u8; 12], tokio::io::Error> {
        let path = format!("{}/nonce", self.config.secret_config.location);

        let nonce = File::open(&path).await;

        let mut f = match nonce {
            Ok(f) => f,
            Err(_) => {
                tracing::info!("Creating nonce...");
                return Self::write_nonce(&path).await;
            }
        };

        let mut n = [0u8; 12];
        f.read_exact(&mut n).await?;

        Ok(n)
    }
    async fn write_nonce(path: &str) -> Result<[u8; 12], tokio::io::Error> {
        let mut f = File::create(&path).await?;

        // Generate nonce
        let mut n = [0u8; 12];
        OsRng::fill_bytes(&mut OsRng, &mut n);

        f.write_all(&n).await?;

        return Ok(n);
    }

    pub async fn get_or_create_certs(
        &self,
    ) -> Result<(Vec<Certificate>, PrivateKey), Box<dyn Error>> {
        if let Ok(mut pubfile) = File::open(&self.config.main_config.cert_path).await &&
            let Ok(mut privfile) = File::open(&self.config.main_config.private_key_path).await {
            // Public key reading
            let mut buf = String::new();
            pubfile.read_to_string(&mut buf).await?;
            let mut buf = Cursor::new(buf);

            // Private key reading
            let mut pbuf = String::new();
            privfile.read_to_string(&mut pbuf).await?;
            let mut pbuf = Cursor::new(pbuf);

            let key = rustls::PrivateKey(rustls_pemfile::pkcs8_private_keys(&mut pbuf)?.remove(0));

            let certs : Vec<rustls::Certificate> = rustls_pemfile::certs(&mut buf)?
                .into_iter()
                .map(rustls::Certificate)
                .collect();

            Ok((certs, key))
        }
        else {
            tracing::warn!("Cannot load certificates. Generating self-signed certificates...");

            let domains = match &self.config.main_config.domains {
                Some(v) => v.clone(),
                None => default_domains().await,
            }.iter().map(std::clone::Clone::clone).collect::<Vec<String>>();

            let cert = rcgen::generate_simple_self_signed(domains)?;
            let key = rustls::PrivateKey(cert.serialize_private_key_der());

            // Saving certificate
            let c = cert.serialize_pem()?;
            let k = cert.serialize_private_key_pem();

            let mut f1 = File::create(&self.config.main_config.cert_path).await?;
            let mut f2 = File::create(&self.config.main_config.private_key_path).await?;

            f1.write_all(c.as_bytes()).await?;
            f2.write_all(k.as_bytes()).await?;

            Ok((vec![rustls::Certificate(cert.serialize_der()?)], key))
        }
    }
    /// Reads from the secrets file using the hashed password
    pub async fn get_secrets(&self, pass : &str) -> Result<SecretConfiguration, ConfigError> {
        let path = format!("{}/secret", self.config.secret_config.location);

        // Reading from the secrets file
        let mut f = File::open(&path).await?;
        let mut cipher = Vec::new();
        f.read_to_end(&mut cipher).await?;

        // Decrypting the cyphertext
        let nonce = self.get_nonce().await?;
        let h = hash_s(pass);
        let mut r = crate::helpers::read_encrypted::<SecretConfiguration>(&h, &nonce, &cipher).await?;

        if self.config.secret_config.restart_key {
            // Set the key to a random key
            r.private_key = Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());
        }

        if r.private_key.is_none() {
            r.private_key = Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());
            self.write_secrets(&r, pass).await?;
        }

        Ok(r)
    }
    /// Serializes the provided [`SecretConfiguration`] and writes it to the secrets file
    pub async fn write_secrets(&self, config : &SecretConfiguration, pass : &str) -> Result<(), tokio::io::Error> {
        let path = format!("{}/secret", self.config.secret_config.location);

        // Get the nonce and hash of the password
        let nonce = self.get_nonce().await?;
        let hash = hash_s(pass);

        // Encrypting the configuration
        let s = crate::helpers::encrypt(&hash, &nonce, config).await;

        let mut f = File::create(&path).await?;
        f.write_all(&s).await?;

        Ok(())
    }
    /// Creates a secrets file, overwriting existing ones
    pub async fn create_secrets(&self, pass : &str) -> Result<SecretConfiguration, tokio::io::Error> {
        let mut secrets = SecretConfiguration::default();
        
        if !self.config.secret_config.restart_key {
            // Set the key to a random key
            secrets.private_key = Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());
        }
        self.write_secrets(&secrets, pass).await?;

        if self.config.secret_config.restart_key {
            secrets.private_key = Some(libsecp256k1::SecretKey::random(&mut OsRng).serialize());
        }

        Ok(secrets)
    }

}

async fn default_domains() -> HashSet<String> {
    let mut ret = HashSet::from_iter(vec!["localhost".to_string()].into_iter());

    let v4 = public_ip::addr_v4().await;
    let v6 = public_ip::addr_v6().await;

    match v4 {
        Some(ip) => {
            ret.insert(ip.to_string());
        }
        _ => {}
    }
    match v6 {
        Some(ip) => {
            ret.insert(ip.to_string());
        }
        _ => {}
    }

    ret
}
