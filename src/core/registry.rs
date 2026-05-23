// src/core/registry.rs
//! Thread-safe, dynamic protocol factory registry.
//!
//! Instead of a monolithic `match` statement in InboundManager/OutboundManager,
//! each protocol registers its factory closure at startup. This allows vendoring
//! new protocols as standalone modules without touching the kernel.

use crate::error::Result;
use crate::inbounds::Inbound;
use crate::outbounds::Outbound;
use crate::protocols::flow_trait::BoxedTrinityTransport;
use dashmap::DashMap;
use std::sync::Arc;

// ─── Factory Traits ───────────────────────────────────────────────────────────

/// A factory that can construct an `Inbound` listener from a JSON config blob.
pub trait InboundFactory: Send + Sync {
    /// Build a ready-to-listen inbound handler from the supplied configuration.
    fn build(&self, config: serde_json::Value) -> Result<Box<dyn Inbound>>;

    /// Human-readable protocol name (e.g. "vless", "trojan", "socks").
    fn protocol_name(&self) -> &str;
}

/// A factory that can construct an `Outbound` handler from a JSON config blob.
pub trait OutboundFactory: Send + Sync {
    /// Build a ready-to-connect outbound handler from the supplied configuration.
    fn build(&self, config: serde_json::Value) -> Result<Arc<dyn Outbound>>;

    /// Human-readable protocol name (e.g. "vless", "freedom", "blackhole").
    fn protocol_name(&self) -> &str;
}

// ─── Closure Adaptors ─────────────────────────────────────────────────────────

/// Adapts a closure `Fn(Value) -> Result<Box<dyn Inbound>>` into an `InboundFactory`.
pub struct InboundFactoryFn<F>
where
    F: Fn(serde_json::Value) -> Result<Box<dyn Inbound>> + Send + Sync,
{
    name: String,
    func: F,
}

impl<F> InboundFactoryFn<F>
where
    F: Fn(serde_json::Value) -> Result<Box<dyn Inbound>> + Send + Sync,
{
    pub fn new(name: impl Into<String>, func: F) -> Self {
        Self {
            name: name.into(),
            func,
        }
    }
}

impl<F> InboundFactory for InboundFactoryFn<F>
where
    F: Fn(serde_json::Value) -> Result<Box<dyn Inbound>> + Send + Sync,
{
    fn build(&self, config: serde_json::Value) -> Result<Box<dyn Inbound>> {
        (self.func)(config)
    }

    fn protocol_name(&self) -> &str {
        &self.name
    }
}

/// Adapts a closure `Fn(Value) -> Result<Arc<dyn Outbound>>` into an `OutboundFactory`.
pub struct OutboundFactoryFn<F>
where
    F: Fn(serde_json::Value) -> Result<Arc<dyn Outbound>> + Send + Sync,
{
    name: String,
    func: F,
}

impl<F> OutboundFactoryFn<F>
where
    F: Fn(serde_json::Value) -> Result<Arc<dyn Outbound>> + Send + Sync,
{
    pub fn new(name: impl Into<String>, func: F) -> Self {
        Self {
            name: name.into(),
            func,
        }
    }
}

impl<F> OutboundFactory for OutboundFactoryFn<F>
where
    F: Fn(serde_json::Value) -> Result<Arc<dyn Outbound>> + Send + Sync,
{
    fn build(&self, config: serde_json::Value) -> Result<Arc<dyn Outbound>> {
        (self.func)(config)
    }

    fn protocol_name(&self) -> &str {
        &self.name
    }
}

// ─── Feature Registry ─────────────────────────────────────────────────────────

/// Thread-safe, lock-free registry of protocol factories.
///
/// Uses `DashMap` for concurrent read/write without blocking the data path.
/// On startup, `register_defaults()` populates this with all built-in protocols.
/// At runtime, `RustrayInstance` queries it by protocol name to spawn handlers.
pub struct FeatureRegistry {
    inbounds: DashMap<String, Box<dyn InboundFactory>>,
    outbounds: DashMap<String, Box<dyn OutboundFactory>>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        let registry = Self {
            inbounds: DashMap::new(),
            outbounds: DashMap::new(),
        };
        registry.register_outbound(ShadowMieruFactory);
        registry
    }

    // ── Registration ──────────────────────────────────────────────────────

    /// Register an inbound protocol factory.
    pub fn register_inbound<F: InboundFactory + 'static>(&self, factory: F) {
        let name = factory.protocol_name().to_string();
        tracing::debug!("Registry: registered inbound factory '{}'", name);
        self.inbounds.insert(name, Box::new(factory));
    }

    /// Register an outbound protocol factory.
    pub fn register_outbound<F: OutboundFactory + 'static>(&self, factory: F) {
        let name = factory.protocol_name().to_string();
        tracing::debug!("Registry: registered outbound factory '{}'", name);
        self.outbounds.insert(name, Box::new(factory));
    }

    /// Convenience: register an inbound factory from a closure.
    pub fn register_inbound_fn<Func>(
        &self,
        name: impl Into<String>,
        func: Func,
    ) where
        Func: Fn(serde_json::Value) -> Result<Box<dyn Inbound>> + Send + Sync + 'static,
    {
        self.register_inbound(InboundFactoryFn::new(name, func));
    }

    /// Convenience: register an outbound factory from a closure.
    pub fn register_outbound_fn<Func>(
        &self,
        name: impl Into<String>,
        func: Func,
    ) where
        Func: Fn(serde_json::Value) -> Result<Arc<dyn Outbound>> + Send + Sync + 'static,
    {
        self.register_outbound(OutboundFactoryFn::new(name, func));
    }

    // ── Lookup ────────────────────────────────────────────────────────────

    /// Create an inbound handler by protocol name.
    pub fn create_inbound(
        &self,
        name: &str,
        config: serde_json::Value,
    ) -> Result<Box<dyn Inbound>> {
        let factory = self
            .inbounds
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Inbound protocol not registered: {}", name))?;
        factory.build(config)
    }

    /// Create an outbound handler by protocol name.
    pub fn create_outbound(
        &self,
        name: &str,
        config: serde_json::Value,
    ) -> Result<Arc<dyn Outbound>> {
        let factory = self
            .outbounds
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Outbound protocol not registered: {}", name))?;
        factory.build(config)
    }

    // ── Introspection ─────────────────────────────────────────────────────

    /// List all registered inbound protocol names.
    pub fn list_inbounds(&self) -> Vec<String> {
        self.inbounds.iter().map(|r| r.key().clone()).collect()
    }

    /// List all registered outbound protocol names.
    pub fn list_outbounds(&self) -> Vec<String> {
        self.outbounds.iter().map(|r| r.key().clone()).collect()
    }

    /// Returns true if an inbound factory is registered for the given protocol name.
    pub fn has_inbound(&self, name: &str) -> bool {
        self.inbounds.contains_key(name)
    }

    /// Returns true if an outbound factory is registered for the given protocol name.
    pub fn has_outbound(&self, name: &str) -> bool {
        self.outbounds.contains_key(name)
    }
}

impl Default for FeatureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Global Singleton ─────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    /// Global protocol registry.  Populated once at startup by `register_defaults()`,
    /// then read concurrently by all inbound/outbound managers.
    pub static ref GLOBAL_REGISTRY: Arc<FeatureRegistry> = Arc::new(FeatureRegistry::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_inbound_not_found() {
        let registry = FeatureRegistry::new();
        let result = registry.create_inbound("nonexistent", serde_json::Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_outbound_not_found() {
        let registry = FeatureRegistry::new();
        let result = registry.create_outbound("nonexistent", serde_json::Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_register_and_list() {
        let registry = FeatureRegistry::new();
        registry.register_inbound_fn("test-proto", |_config| {
            Err(anyhow::anyhow!("test factory"))
        });
        assert!(registry.has_inbound("test-proto"));
        assert!(!registry.has_inbound("other"));
        assert_eq!(registry.list_inbounds(), vec!["test-proto".to_string()]);
    }
}

// ─── ShadowMieru factory & outbound ──────────────────────────────────────────

pub struct ShadowMieruFactory;

impl OutboundFactory for ShadowMieruFactory {
    fn build(&self, config: serde_json::Value) -> Result<Arc<dyn Outbound>> {
        let smr_settings: crate::config::ShadowMieruConfig = serde_json::from_value(config)?;
        Ok(Arc::new(ShadowMieruOutbound {
            settings: smr_settings,
        }))
    }

    fn protocol_name(&self) -> &str {
        "shadow_mieru"
    }
}

pub struct ShadowMieruOutbound {
    settings: crate::config::ShadowMieruConfig,
}

#[async_trait::async_trait]
impl crate::outbounds::Outbound for ShadowMieruOutbound {
    async fn handle(
        &self,
        mut in_stream: BoxedTrinityTransport,
        host: String,
        port: u16,
        _policy: Arc<crate::config::LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;
        let _ = tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream).await;
        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedTrinityTransport> {
        let dns_server = crate::app::stats::StatsManager::global()
            .map(|s| s.dns_server.clone())
            .ok_or_else(|| anyhow::anyhow!("StatsManager not initialized"))?;
        let stream = crate::transport::connect(&crate::config::StreamSettings::default(), dns_server, &host, port).await?;
        
        let mut key = [0u8; 16];
        if let Ok(decoded) = hex::decode(&self.settings.entropy_key) {
            let len = decoded.len().min(16);
            key[..len].copy_from_slice(&decoded[..len]);
        }
        
        let smr_stream = crate::transport::shadow_mieru::ShadowMieruStream::new(
            stream,
            key,
            self.settings.pacing_mbps * 1_000_000,
            &self.settings.decoy_profile,
            &self.settings.padding_profile,
        );
        Ok(Box::new(smr_stream) as BoxedTrinityTransport)
    }
}

