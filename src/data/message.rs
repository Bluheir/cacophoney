use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::crypto::PubKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The message header, or code
    #[serde(rename = "h")]
    pub header: u8,

    /// The object contained in the packet
    #[serde(rename = "obj")]
    pub object: serde_cbor::Value,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct Identifier {
    pub key: PubKey,
    pub timestamp: u64,
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}
