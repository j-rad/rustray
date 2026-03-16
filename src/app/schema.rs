// src/app/schema.rs
//! SurrealQL Schema Definitions
//!
//! Formal schema definitions for all database tables with migration support.

/// SurrealQL schema for servers table
pub const SERVERS_SCHEMA: &str = r#"
-- Define servers table with schema enforcement
DEFINE TABLE servers SCHEMAFULL;

-- Fields
DEFINE FIELD name ON TABLE servers TYPE string;
DEFINE FIELD subscription_id ON TABLE servers TYPE option<string>;
DEFINE FIELD encrypted_outbound ON TABLE servers TYPE bytes;
DEFINE FIELD nonce ON TABLE servers TYPE bytes;
DEFINE FIELD protocol ON TABLE servers TYPE string;
DEFINE FIELD latency_ms ON TABLE servers TYPE option<number>;
DEFINE FIELD last_connected ON TABLE servers TYPE option<number>;

-- Indexes
DEFINE INDEX idx_protocol ON TABLE servers COLUMNS protocol;
DEFINE INDEX idx_subscription ON TABLE servers COLUMNS subscription_id;
"#;

/// SurrealQL schema for subscriptions table
pub const SUBSCRIPTIONS_SCHEMA: &str = r#"
-- Define subscriptions table
DEFINE TABLE subscriptions SCHEMAFULL;

-- Fields
DEFINE FIELD name ON TABLE subscriptions TYPE string;
DEFINE FIELD url ON TABLE subscriptions TYPE string;
DEFINE FIELD last_updated ON TABLE subscriptions TYPE number;
DEFINE FIELD auto_update ON TABLE subscriptions TYPE bool;

-- Indexes
DEFINE INDEX idx_name ON TABLE subscriptions COLUMNS name;
"#;

/// SurrealQL schema for routing_rules table
pub const ROUTING_RULES_SCHEMA: &str = r#"
-- Define routing_rules table
DEFINE TABLE routing_rules SCHEMAFULL;

-- Fields
DEFINE FIELD name ON TABLE routing_rules TYPE string;
DEFINE FIELD description ON TABLE routing_rules TYPE string;
DEFINE FIELD domain_rules ON TABLE routing_rules TYPE array<string>;
DEFINE FIELD ip_rules ON TABLE routing_rules TYPE array<string>;
DEFINE FIELD target_tag ON TABLE routing_rules TYPE string;
DEFINE FIELD active ON TABLE routing_rules TYPE bool;

-- Indexes
DEFINE INDEX idx_active ON TABLE routing_rules COLUMNS active;
DEFINE INDEX idx_target ON TABLE routing_rules COLUMNS target_tag;
"#;

/// Run all schema migrations
/// Run all schema migrations
#[cfg(feature = "surrealdb")]
pub async fn run_migrations(
    db: &surrealdb::Surreal<surrealdb::engine::local::Db>,
) -> anyhow::Result<()> {
    use tracing::info;

    info!("Running SurrealDB schema migrations...");

    // Execute servers schema
    db.query(SERVERS_SCHEMA).await?;
    info!("✓ Servers schema migrated");

    // Execute subscriptions schema
    db.query(SUBSCRIPTIONS_SCHEMA).await?;
    info!("✓ Subscriptions schema migrated");

    // Execute routing_rules schema
    db.query(ROUTING_RULES_SCHEMA).await?;
    info!("✓ Routing rules schema migrated");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schemas_not_empty() {
        assert!(!SERVERS_SCHEMA.is_empty());
        assert!(!SUBSCRIPTIONS_SCHEMA.is_empty());
        assert!(!ROUTING_RULES_SCHEMA.is_empty());
    }

    #[test]
    fn test_schemas_contain_define() {
        assert!(SERVERS_SCHEMA.contains("DEFINE TABLE"));
        assert!(SUBSCRIPTIONS_SCHEMA.contains("DEFINE TABLE"));
        assert!(ROUTING_RULES_SCHEMA.contains("DEFINE TABLE"));
    }
}
