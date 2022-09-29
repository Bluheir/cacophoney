pub mod file;
pub mod ip;

pub fn hash_s(s: &String) -> [u8; 32] {
    blake3::hash(s.as_bytes()).as_bytes().clone()
}
