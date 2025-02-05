use std::sync::Mutex;

use actix_web::{
    App, HttpResponse, HttpServer, Responder, get, post,
    web::{Data, Query},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use rs_merkle::{Hasher, MerkleTree, algorithms::Sha256};
use rusqlite::Connection;

use serde::Deserialize;
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
    let db = state.db.lock().unwrap();
    db.execute(
        "CREATE TABLE IF NOT EXISTS db(
id INTEGER PRIMARY KEY NOT NULL,
file TEXT NOT NULL,
nonce TEXT NOT NULL
);",
        [],
    )
    .unwrap();
    drop(db);
    println!("starting server");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(get_file)
            .service(store_file)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[derive(Deserialize)]
struct GetQuery {
    id: usize,
}

#[get("/file")]
async fn get_file(server_state: Data<ServerState>, id: Query<GetQuery>) -> impl Responder {
    println!("request file: {}", id.id);
    let db = server_state.db.lock().unwrap();
    let tree = server_state.tree.lock().unwrap();
    let file: String = db
        .query_row("SELECT file FROM db WHERE id=?1", [id.id], |row| row.get(0))
        .unwrap();

    let encrypted_file: EncryptedFile = serde_json::from_str(&file).unwrap();

    let hash = Sha256::hash(&BASE64_STANDARD.decode(&file).unwrap());

    let levaves = tree.leaves().unwrap();
    let index = levaves.iter().position(|leaf| *leaf == hash).unwrap();

    let proof = tree.proof(&[index]).to_bytes();

    let res = GetResponse {
        nonce: encrypted_file.nonce,
        file: encrypted_file.file,
        index,
        length: tree.leaves_len(),
        proof,
        root: tree.root_hex().unwrap(),
    };

    HttpResponse::Ok().json(res)
}

#[post("/file")]
async fn store_file(server_state: Data<ServerState>, body: String) -> impl Responder {
    let file: EncryptedFile = serde_json::from_str(&body).unwrap();
    let db = server_state.db.lock().unwrap();
    let mut tree = server_state.tree.lock().unwrap();

    println!("push file {}", file.file);

    let _ = db.execute("INSERT INTO db (file, nonce) VALUES (?1, ?2)", [
        file.file.clone(),
        BASE64_STANDARD.encode(file.nonce),
    ]);

    let id: usize = db.query_row("SELECT id FROM db WHERE file=?1", [file.file.clone()], |row| row.get(0)).unwrap();

    let hash = Sha256::hash(&BASE64_STANDARD.decode(file.file.clone()).unwrap());
    tree.insert(hash).commit();

    let levaves = tree.leaves().unwrap();
    let index = levaves.iter().position(|leaf| *leaf == hash).unwrap();

    let proof = tree.proof(&[index]).to_bytes();

    let res = PostResponse {
        id,
        root: tree.root_hex().unwrap(),
        index,
        length: tree.leaves_len(),
        proof,
    };

    HttpResponse::Ok().json(res)
}
