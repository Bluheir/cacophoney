use serde::{Deserialize, Serialize};

use super::crypto::PubKey;

#[derive(Serialize, Deserialize, Clone)]
/// Represents a User who can send messages to other clients or could store other messages
pub struct User {
    /// My "Master" nickname
    pub nickname: String,
    /// My public key
    pub pub_key: PubKey,
}
pub struct SubAccount {
    /// My public key
    pub pub_key: PubKey,
}
