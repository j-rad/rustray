use surrealdb::Surreal;
use surrealdb::engine::local::{Db, SurrealKv};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use tracing::info;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub email: String,
    pub traffic: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Inbound {
    pub protocol: String,
    pub port: u16,
    pub settings: serde_json::Value,
}

pub struct DbManager {
    pub db: Surreal<Db>,
}

impl DbManager {
    pub async fn new(path: &str) -> Result<Self> {
        info!("Connecting to embedded SurrealDB (SurrealKV) at {}", path);
        let db = Surreal::new::<SurrealKv>(path).await?;
        db.use_ns("rustray").use_db("panel").await?;
        
        let manager = Self { db };
        manager.init_schema().await?;
        
        Ok(manager)
    }

    async fn init_schema(&self) -> Result<()> {
        info!("Initializing SurrealDB schema for rustray panel...");
        
        self.db.query("
            DEFINE TABLE user SCHEMALESS;
            DEFINE INDEX user_email ON TABLE user FIELDS email UNIQUE;
            DEFINE INDEX traffic_lookup ON TABLE user FIELDS traffic;

            DEFINE TABLE inbound SCHEMALESS;
        ").await?;
        
        Ok(())
    }

    /// Atomically adds a new user or updates existing one
    pub async fn add_user(&self, id: &str, email: &str) -> Result<()> {
        let user = User {
            email: email.to_string(),
            traffic: 0,
        };
        let _: Option<User> = self.db.upsert(("user", id))
            .content(user)
            .await?;
        Ok(())
    }

    /// Atomically increments traffic for a user
    pub async fn increment_traffic(&self, user_id: &str, amount: u64) -> Result<()> {
        let query = "UPDATE type::record($user_id) SET traffic += $amount";
        self.db.query(query)
            .bind(("user_id", format!("user:{}", user_id)))
            .bind(("amount", amount))
            .await?;
        Ok(())
    }

    pub async fn get_all_users(&self) -> Result<Vec<(String, User)>> {
        let mut response = self.db.query("SELECT id, email, traffic FROM user").await?;
        let users: Vec<serde_json::Value> = response.take(0)?;
        
        let mut result = Vec::new();
        for v in users {
            if let Some(id) = v.get("id").and_then(|id| id.as_str()) {
                let user: User = serde_json::from_value(v.clone())?;
                result.push((id.to_string(), user));
            }
        }
        Ok(result)
    }

    pub async fn get_all_inbounds(&self) -> Result<Vec<Inbound>> {
        let inbounds: Vec<Inbound> = self.db.select("inbound").await?;
        Ok(inbounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_db_manager_lifecycle() -> Result<()> {
        let dir = tempdir()?;
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let manager = DbManager::new(db_path_str).await?;

        // Test user addition
        manager.add_user("user1", "test@example.com").await?;

        // Test traffic increment
        manager.increment_traffic("user1", 1024).await?;

        // Test retrieval
        let users = manager.get_all_users().await?;
        let found = users.iter().find(|(id, _)| id == "user:user1");
        assert!(found.is_some());
        let (_, user) = found.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.traffic, 1024);

        Ok(())
    }
}
