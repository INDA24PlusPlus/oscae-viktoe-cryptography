use rand::Rng;
use std::env::args;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use base64::{encode, decode};

use aes_gcm::{Aes256Gcm, Key, Nonce}; 
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, PasswordHasher, PasswordHash, password_hash::SaltString};


struct EncryptedFile {
    nonce: [u8; 12],
    file: String, // base64 encoded
}

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Upload a file
    Upload {
        /// Password for encryption
        password: String,
        /// File path to upload
        file_path: String,
    },
    /// Download a file
    Download {
        /// Password for decryption
        password: String,
        /// File ID to download
        file_id: usize,
        /// Output file path
        outfile: String,
    },
}

fn main() {
    // skip 1 to ignore the first argument which is the name of the program
    let args = Args::parse();

    match args.command {
        Commands::Upload { password, file_path } => {
            
            send_file(&password, &file_path);
        }
        Commands::Download { password, file_id, outfile } => {
            request_file(&password, file_id, &outfile);
        }
    }
}

fn send_file(password: &str, file: &str) {
    // get a key from the password
    let key = key_from_password(password);

    // read file
    let data = read_file(file);

    // encrypt file with password
    let encrypted_data = encrypt_data(&data, &key);

    // send file to server
    send_data(&encrypted_data);
}

fn send_data(data: &EncryptedFile) -> Result<(), Box<dyn Error>> {
    let url = "172.0.0.1:8080/file";
    let client = Client::new();
    let response: Response = client.post(&url)
        .json(data)
        .send()?;
    if response.status().is_success() {
        todo!("print id of uploaded file");
        Ok(())
    } else {
        Err(Box::from("Failed to upload data"))
    }
}

fn read_file(path: &str) -> Vec<u8> {
    let mut file = File::open(path).expect("File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    buffer
}

fn encrypt_data(data: &Vec<u8>, key: &Key<Aes256Gcm>) -> EncryptedFile {
    // nonce
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // encrypt data
    let cipher = Aes256Gcm::new(key);
    let encrypted_data = cipher.encrypt(&nonce, data.as_ref()).unwrap();
    EncryptedFile {
        nonce: nonce_bytes,
        file: base64::encode(&encrypted_data),
    }
}

fn key_from_password(password: &str) -> Key<Aes256Gcm> {
    let string = "what do you call a cow with no legs? ground beef";
    let salt: &[u8] = string.as_bytes();

    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt).unwrap();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt_string).unwrap();
    let key_bytes = password_hash.hash.unwrap().as_bytes()[..32].to_vec();
    Key::<Aes256Gcm>::from_slice(&key_bytes).to_owned()
}

fn request_file(password: &str, id: usize, outfile: &str) {
    // get a key from the password
    let key = key_from_password(password);

    // request file from server
    let encrypted_data = request_data(id);

    // decrypt file with password
    let data = decrypt_data(encrypted_data, &key);

    // write file
    write_file(&data, outfile);
}

fn request_data(id: usize) -> Result<EncryptedFile, Box<dyn Error>> {
    todo!();
    let url = format!("127.0.0.1:8080/file?id={}", id);
    let response = Client::new().get(&url).send()?;
    let encrypted_file// = response.json()?;
    Ok(encrypted_file)
}

fn decrypt_data(data: EncryptedFile, key: &Key<Aes256Gcm>) -> Vec<u8> {
    // decrypt data
    let nonce = Nonce::from_slice(data.nonce.as_ref());
    let data = base64::decode(data.file).expect("Error decoding base64 from server");
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, data.as_ref()).unwrap()
}

fn write_file(data: &Vec<u8>, path: &str) {
    let mut file = File::create(path).expect("Failed to create file");
    file.write_all(data).expect("Failed to write file");
}

