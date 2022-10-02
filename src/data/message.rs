use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::crypto::PubKey;

/// Represents a header for a message
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessageHeader {
    /// A client identifies the stream type
    StreamIdentify = 0,
    /// A client identifies themself with a public key
    Identify = 1,
    /// An error
    Error = 2,
}
/// Represents a generic message received by/sent to a client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The message header, or code
    #[serde(rename = "h")]
    pub header: MessageHeader,

    /// The object contained in the packet
    #[serde(rename = "obj")]
    pub object: serde_cbor::Value,
}
/// A client identifying themself with a stream ID
#[derive(Clone, Serialize, Deserialize)]
pub enum StreamIdentify {
    /// A normal stream with normal events
    Normal = 0,
    Administration = 1,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct Identifier {
    /// Public keys and signatures
    pub identities: Vec<Identity>,
    /// Timestamp of the identify
    pub timestamp: DateTime<Utc>,
    /// The code that the client/server sent in an identify request
    #[serde_as(as = "[_; 32]")]
    pub sig_msg: [u8; 32],
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Public key identifying as
    pub key: PubKey,
    /// Digital signature of the timestamp
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}
