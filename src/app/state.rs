use crate::config::Config;
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use tokio::sync::watch;

/// Global application state shared across Actix-web handlers and the proxy engine.
pub struct GlobalState {
    /// Handle to the embedded SurrealDB instance.
    pub db: Surreal<Db>,
    /// Watch channel sender for real-time configuration updates to the proxy engine.
    pub config_tx: watch::Sender<Config>,
}

impl GlobalState {
    /// Create a new GlobalState instance.
    pub fn new(db: Surreal<Db>, config_tx: watch::Sender<Config>) -> Self {
        Self { db, config_tx }
    }
}
