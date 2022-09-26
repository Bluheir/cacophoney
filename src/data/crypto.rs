use std::{error::Error, ops::Deref};

use libsecp256k1::{verify, Message, PublicKey, Signature};
use serde::{de::Visitor, Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Clone, Copy)]
pub struct PubKey {
    /// My compressed public key
    pub key: [u8; 33],
    verif: Option<PublicKey>,
}

impl PubKey {
    pub fn new(key: [u8; 33]) -> Self {
        Self { key, verif: None }
    }
    fn verify(&mut self, msg: &[u8], sig: &[u8; 64]) -> Result<bool, Box<dyn Error>> {
        let hash = blake3::hash(msg);

        self.verify_hash(hash.as_bytes(), sig)
    }

    fn verify_hash(&mut self, hash: &[u8; 32], sig: &[u8; 64]) -> Result<bool, Box<dyn Error>> {
        let key = match &self.verif {
            Some(v) => v,
            None => {
                // Convert to public key
                self.verif = Some(PublicKey::parse_compressed(&self.key)?);
                self.verif.as_ref().unwrap()
            }
        };
        // Convert to signature
        let signature = Signature::parse_standard(sig)?;

        let msg = Message::parse(hash);

        Ok(verify(&msg, &signature, key))
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.key)
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(PubKeyVisitor {})
    }
}

impl Deref for PubKey {
    type Target = [u8; 33];

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}
impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

struct PubKeyVisitor;

impl<'de> Visitor<'de> for PubKeyVisitor {
    type Value = PubKey;

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != 33 {
            return Err(E::custom("pub key length must be 33 bytes"));
        }

        // Cannot fail
        Ok(PubKey::new(v.try_into().unwrap()))
    }
    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != 33 {
            return Err(E::custom("pub key length must be 33 bytes"));
        }

        // Cannot fail
        Ok(PubKey::new(v.try_into().unwrap()))
    }

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting bytes of exactly length 33")
    }
}
