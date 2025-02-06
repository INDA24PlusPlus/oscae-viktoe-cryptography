use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub nonce: [u8; 12],
    pub file: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetResponse {
    pub nonce: [u8; 12],
    pub file: String,
    pub root: [u8; 32],
    pub index: usize,
    pub length: usize,
    pub proof: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct PostResponse {
    pub id: usize,
    pub root: [u8; 32],
    pub index: usize,
    pub length: usize,
    pub proof: Vec<u8>
}
