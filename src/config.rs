use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Configuration {
    #[serde(default)]
    pub quic: NetworkConfiguration,
    #[serde(default)]
    pub proxy: NetworkConfiguration,
    #[serde(default)]
    #[serde(rename = "main")]
    pub main_config: MainConfiguration,
    #[serde(default)]
    pub secret_config: SecretFileConfiguration,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretFileConfiguration {
    /// The path to the encrypted secrets file
    #[serde(default = "default_secret_location")]
    pub location: String,
    /// The password to unlock the secrets file. If null, you will be prompted to type the password when the node turns on.
    #[serde(default)]
    pub password: Option<String>,
    /// Reset the private key every time the node is turned on. `private_key` must be null in the secrets file for this option to have any effect.
    /// If turned off and `private_key` is null, the file will be edited with a random private key.
    #[serde(default = "default_restart_key")]
    pub restart_key: bool,
}

impl Default for SecretFileConfiguration {
    fn default() -> Self {
        SecretFileConfiguration {
            location: default_secret_location(),
            password: None,
            restart_key: default_restart_key(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SecretConfiguration {
    #[serde(default)]
    pub private_key: Option<[u8; 32]>,
    /// The password to unlock the certificate
    #[serde(default)]
    pub cert_password: Option<String>,
    /// A password for client administrative privileges. If [`None`], no client can administrate the server.
    #[serde(default)]
    pub admin_pass: Option<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkConfiguration {
    /// The address to listen on
    #[serde(default = "default_addr")]
    pub address: String,
    /// The port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for NetworkConfiguration {
    fn default() -> Self {
        Self {
            address: default_addr(),
            port: default_port(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MainConfiguration {
    /// The services provided by the server
    #[serde(default = "default_features")]
    pub features: HashSet<String>,
    /// The protocol version number, e.g 1.0.0
    pub version: String,
    /// File path of the certificate
    #[serde(default)]
    pub cert_path: String,
    /// Private key path of the certificate
    #[serde(default)]
    pub private_key_path: String,
}

impl Default for MainConfiguration {
    fn default() -> Self {
        Self {
            features: default_features(),
            version: default_version(),
            cert_path: default_pubkey(),
            private_key_path: default_privkey(),
        }
    }
}

fn default_addr() -> String {
    "::/0".to_string()
}
fn default_port() -> u16 {
    56665
}
fn default_features() -> HashSet<String> {
    HashSet::from_iter(
        vec![
            "base".to_string(),
            "proxy".to_string(),
            "proxy/json5".to_string(),
            "proxy/json".to_string(), // Recommended
            "storage".to_string(),
        ]
        .into_iter(),
    )
}
fn default_version() -> String {
    "0.1.0".to_string()
}
fn default_secret_location() -> String {
    "./secrets/secret".to_string()
}
fn default_restart_key() -> bool {
    true
}

fn default_pubkey() -> String {
    "./cert.pem".to_string()
}
fn default_privkey() -> String {
    "./key.pem".to_string()
}

pub static DEFAULT_CONFIG: &str = r##"
[main]
# Do not change
version = "0.1.0"
# SSL needs to be configured before secure can be set to true
secure = false
# File path of the certificate
cert_path = "./cert.pem"
# Private key path of the certificate
private_key_path = "./key.pem"

# All the services of the server
features = [
    "base",
    "proxy", 
    "proxy/json5",
    
    # Recommended
    "proxy/json",
    
    "storage",
]

[secret_config]
# The path to the encrypted secrets file
location = "./secrets/secret"
# Reset the private key every time the node is turned on. `private_key` must be null in the secrets file for this option to have any effect.
# If turned off and `private_key` is null, the file will be edited with a random private key.
restart_key = true
# The password to unlock the secrets file. If null, you will be prompted to type the password when the node turns on.
# password = ""

[quic]
address = "::/0"
port = 56665

[proxy]
address = "::/0"
# Change to 443 if using SSL
port = 80
"##;
