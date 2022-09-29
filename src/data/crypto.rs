use std::{error::Error, ops::Deref};

use byteorder::{WriteBytesExt, LittleEndian};
use chrono::{DateTime, Utc};
use libsecp256k1::{verify, Message, PublicKey, Signature, SecretKey};
use serde::{de::Visitor, Deserialize, Serialize};
use serde_with::serde_as;

use super::Identity;

#[derive(Clone, Copy)]
pub struct PubKey {
    /// The compressed public key
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

impl Default for PubKey {
    fn default() -> Self {
        Self::new([0u8; 33])
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
    fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        
        Ok(PubKey::default())
    }

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting bytes of exactly length 33")
    }
}

/// Wrapper around [`SecretKey`] with [`Serialize`] and [`Deserialize`] implementation
#[derive(Copy, Clone)]
pub struct PrivKey {
    key : SecretKey,
}

impl PrivKey {
    pub fn new(key : [u8; 32]) -> Result<Self, libsecp256k1::Error> {
        Ok(PrivKey {
            key : SecretKey::parse(&key)?
        })
    }
    pub fn sign_hash(&self, msg : &[u8; 32]) -> [u8; 64] {
        let msg = libsecp256k1::Message::parse(msg);
        libsecp256k1::sign(&msg, &self.key).0.serialize()
    }
    pub fn sign(&self, msg : &[u8]) -> [u8; 64] {
        self.sign_hash(blake3::hash(msg).as_bytes())
    }
}

impl Serialize for PrivKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_bytes(&self.key.serialize())
    }
}

struct PrivKeyVisitor;

impl<'de> Visitor<'de> for PrivKeyVisitor {
    type Value = PrivKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting bytes of exactly length 32")
    }
    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != 32 {
            return Err(E::custom("priv key length must be 32 bytes"));
        }

        // Cannot fail
        Ok(PrivKey::new(v.try_into().unwrap()).unwrap())
    }
    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != 32 {
            return Err(E::custom("priv key length must be 32 bytes"));
        }

        // Cannot fail
        Ok(PrivKey::new(v.try_into().unwrap()).unwrap())
    }
}
impl<'de> Deserialize<'de> for PrivKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        deserializer.deserialize_bytes(PrivKeyVisitor)
    }
}

/// A type for a signed message
pub enum SigmsgType {
    /// A dummy message. Used for identifying public keys to clients and servers
    Dummy = 0
}

/// A message that can be serialized, hashed, then signed. 
/// Can also be constructed from other types and then verified from an existing signature.
#[derive(Clone)]
pub struct SignedMsg {
    /// Hashed message
    hash : blake3::Hash
}

impl SignedMsg {
    pub fn from_identity(sig_msg : &[u8; 32], timestamp : &DateTime<Utc>) -> Self {
        let mut contents = Vec::new();

        // Write header byte
        contents.write_u8(SigmsgType::Dummy as u8);
        // Write sig_msg
        contents.extend(sig_msg);
        // Write timestamp as millis. Always little endian.
        contents.write_i64::<LittleEndian>(timestamp.timestamp_millis());

        Self {
            hash : blake3::hash(&contents)
        }
    }
    /// Returns the hash of the converted message
    pub fn hash(&self) -> &[u8; 32] {
        self.hash.as_bytes()
    }
    /// Verifies the message
    pub fn verify(&self, key : &mut PubKey, sig : &[u8; 64]) -> Result<bool, Box<dyn Error>> {
        key.verify_hash(self.hash(), sig)
    }
    pub fn sign(&self, key : &PrivKey) -> [u8; 64] {
        key.sign_hash(self.hash())
    }
}