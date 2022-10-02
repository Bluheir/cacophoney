use serde::{Deserialize, Serialize};

use super::crypto::PubKey;

/// Represents a User who can send messages to other clients or could store other messages
#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    /// Master nickname of the user
    pub nickname: String,
    /// Public key of the user
    pub pub_key: PubKey,
}
/// Represents an account that receives messages
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct SubAccount {
    /// My public key
    pub pub_key: PubKey,
    pub publicity: Publicity,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Publicity {
    Public,
    Private,
}
