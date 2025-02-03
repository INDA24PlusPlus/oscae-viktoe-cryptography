use std::sync::Mutex;

use actix_web::{
    App, HttpResponse, HttpServer, Responder, get, post,
    web::{Data, Query},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use rs_merkle::{Hasher, MerkleTree, algorithms::Sha256};
use rusqlite::Connection;

use shared::{EncryptedFile, GetResponse, PostResponse};

struct ServerState {
    db: Mutex<Connection>,
    tree: Mutex<MerkleTree<Sha256>>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            db: Mutex::new(Connection::open_in_memory().unwrap()),
            tree: Mutex::new(MerkleTree::<Sha256>::new()),
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = Data::new(ServerState::default());
    HttpServer::new(move || App::new().app_data(state.clone()).service(get_file))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

#[get("/file")]
async fn get_file(server_state: Data<ServerState>, id: Query<usize>) -> impl Responder {
    let db = server_state.db.lock().unwrap();
    let tree = server_state.tree.lock().unwrap();
    let file: String = db
        .query_row("SELECT file FROM db WHERE id=$1", [id.0], |row| row.get(0))
        .unwrap();

    let encrypted_file: EncryptedFile = serde_json::from_str(&file).unwrap();

    let hash = Sha256::hash(&BASE64_STANDARD.decode(&file).unwrap());

    let levaves = tree.leaves().unwrap();
    let index = levaves
        .iter()
        .position(|leaf| *leaf == hash)
        .unwrap();

    let proof = tree.proof(&[index]).to_bytes();

    let res = GetResponse {
        nonce: encrypted_file.nonce,
        file: encrypted_file.file,
        index,
        length: tree.leaves_len(),
        proof,
        root: tree.root_hex().unwrap()
    };

    HttpResponse::Ok().json(res)

}

#[post("/file")]
async fn store_file(server_state: Data<ServerState>, body: String) -> impl Responder {
    let file: EncryptedFile = serde_json::from_str(&body).unwrap();
    let db = server_state.db.lock().unwrap();
    let mut tree = server_state.tree.lock().unwrap();

    let _ = db.execute("INSERT INTO db (file, nonce) VALUES (?1, ?2)", [
        file.file.clone(),
        BASE64_STANDARD.encode(file.nonce),
    ]);

    let hash = Sha256::hash(&BASE64_STANDARD.decode(file.file.clone()).unwrap());
    tree.insert(hash).commit();

    let levaves = tree.leaves().unwrap();
    let index = levaves
        .iter()
        .position(|leaf| *leaf == hash)
        .unwrap();

    let proof = tree.proof(&[index]).to_bytes();

    let res = PostResponse {
        root: tree.root_hex().unwrap(),
        index,
        length: tree.leaves_len(),
        proof
    };

    HttpResponse::Ok().json(res)
}
