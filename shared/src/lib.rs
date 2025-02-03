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
    pub root: String,
    pub index: usize,
    pub length: usize,
    pub proof: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct PostResponse {
    pub root: String,
    pub index: usize,
    pub length: usize,
    pub proof: Vec<u8>
}
