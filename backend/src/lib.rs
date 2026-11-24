pub mod api;
pub mod collector;
pub mod contracts;
pub mod cve;
pub mod dashboard;
pub mod dataset;
pub mod db;
pub mod detection;
pub mod gateway;
pub mod knowledge;
pub mod lab_analysis;
pub mod log_formats;
pub mod mcp;
pub mod observability;
pub mod provider;
pub mod retention;
pub mod review;
pub mod secrets;
pub mod services;
pub mod structure;
use std::sync::Arc;
use tokio::sync::Mutex;
#[derive(Clone)]
pub struct App {
    pub pool: sqlx::PgPool,
    pub client: reqwest::Client,
    pub config: Arc<Config>,
    pub volatile_key: Arc<Mutex<Option<String>>>,
    pub authorization: Arc<Mutex<Option<gateway::Authorization>>>,
    pub leadership: Arc<std::sync::atomic::AtomicBool>,
}
pub struct Config {
    pub log_root: String,
    pub embeddings_url: String,
    pub admin_secret: String,
    pub origin: String,
    pub session_id: String,
    pub master_key: Option<String>,
}
pub const MODEL_REV: &str = "614241f622f53c4eeff9890bdc4f31cfecc418b3";
pub fn hash(data: impl AsRef<[u8]>) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}
