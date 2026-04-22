// src/app/policy/mod.rs
use crate::config::{LevelPolicy, PolicyConfig};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug)]
pub struct PolicyManager {
    policies: HashMap<u32, Arc<LevelPolicy>>,
    default_policy: Arc<LevelPolicy>,
}

impl PolicyManager {
    pub fn new(config: PolicyConfig) -> Self {
        let levels = config.levels.unwrap_or_default();
        let default_policy = Arc::new(levels.get(&0).cloned().unwrap_or_default());
        Self { policies: HashMap::new(), default_policy }
    }

    pub fn get_policy(&self, level: u32) -> Arc<LevelPolicy> {
        self.policies.get(&level).cloned().unwrap_or_else(|| self.default_policy.clone())
    }
}