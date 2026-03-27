// src/plugin/sip003.rs
//! SIP003 Plugin Interoperability
//!
//! Implements the SIP003 plugin specification used by Shadowsocks-compatible
//! transports. Parses plugin environment variables and manages child process
//! lifecycle for external transport plugins.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use tracing::info;

/// SIP003 environment variable names.
pub const SS_REMOTE_HOST: &str = "SS_REMOTE_HOST";
pub const SS_REMOTE_PORT: &str = "SS_REMOTE_PORT";
pub const SS_LOCAL_HOST: &str = "SS_LOCAL_HOST";
pub const SS_LOCAL_PORT: &str = "SS_LOCAL_PORT";
pub const SS_PLUGIN_OPTIONS: &str = "SS_PLUGIN_OPTIONS";

/// Parsed SIP003 plugin configuration.
#[derive(Debug, Clone)]
pub struct Sip003Config {
    pub remote_host: String,
    pub remote_port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub plugin_options: HashMap<String, String>,
}

impl Sip003Config {
    /// Parse SIP003 env vars from the current environment.
    pub fn from_env() -> io::Result<Self> {
        let remote_host = std::env::var(SS_REMOTE_HOST)
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let remote_port: u16 = std::env::var(SS_REMOTE_PORT)
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let local_host = std::env::var(SS_LOCAL_HOST)
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let local_port: u16 = std::env::var(SS_LOCAL_PORT)
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let plugin_options = Self::parse_options(
            &std::env::var(SS_PLUGIN_OPTIONS).unwrap_or_default(),
        );

        Ok(Self {
            remote_host,
            remote_port,
            local_host,
            local_port,
            plugin_options,
        })
    }

    /// Parse from explicit values (for testing or programmatic use).
    pub fn new(
        remote_host: String,
        remote_port: u16,
        local_host: String,
        local_port: u16,
        options_str: &str,
    ) -> Self {
        Self {
            remote_host,
            remote_port,
            local_host,
            local_port,
            plugin_options: Self::parse_options(options_str),
        }
    }

    /// Parse SIP003 plugin options string (semicolon-separated key=value pairs).
    /// Example: "obfs=tls;obfs-host=www.example.com;mux=4"
    fn parse_options(options: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if options.is_empty() {
            return map;
        }

        for part in options.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((key, value)) = part.split_once('=') {
                map.insert(key.trim().to_string(), value.trim().to_string());
            } else {
                // Boolean flag (key without value)
                map.insert(part.to_string(), String::new());
            }
        }

        map
    }

    /// Get the remote address as a SocketAddr.
    pub fn remote_addr(&self) -> io::Result<SocketAddr> {
        format!("{}:{}", self.remote_host, self.remote_port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// Get the local address as a SocketAddr.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        format!("{}:{}", self.local_host, self.local_port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// Get a plugin option by key.
    pub fn option(&self, key: &str) -> Option<&str> {
        self.plugin_options.get(key).map(|s| s.as_str())
    }

    /// Check if a boolean flag option is set.
    pub fn has_flag(&self, key: &str) -> bool {
        self.plugin_options.contains_key(key)
    }

    /// Build environment variables map for a child plugin process.
    pub fn build_env_vars(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert(SS_REMOTE_HOST.to_string(), self.remote_host.clone());
        env.insert(SS_REMOTE_PORT.to_string(), self.remote_port.to_string());
        env.insert(SS_LOCAL_HOST.to_string(), self.local_host.clone());
        env.insert(SS_LOCAL_PORT.to_string(), self.local_port.to_string());

        // Reconstruct options string
        let options: Vec<String> = self
            .plugin_options
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{}={}", k, v)
                }
            })
            .collect();
        env.insert(SS_PLUGIN_OPTIONS.to_string(), options.join(";"));

        env
    }
}

/// SIP003 plugin process manager.
pub struct PluginProcess {
    child: tokio::process::Child,
    config: Sip003Config,
}

impl PluginProcess {
    /// Launch a SIP003 plugin as a child process.
    pub async fn launch(
        plugin_path: &str,
        config: Sip003Config,
    ) -> io::Result<Self> {
        let env_vars = config.build_env_vars();

        info!(
            "SIP003: launching plugin '{}' (local={}:{}, remote={}:{})",
            plugin_path,
            config.local_host,
            config.local_port,
            config.remote_host,
            config.remote_port,
        );

        let child = tokio::process::Command::new(plugin_path)
            .envs(&env_vars)
            .kill_on_drop(true)
            .spawn()?;

        // Give the plugin time to bind its port
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        Ok(Self { child, config })
    }


    /// Check if the plugin process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Get the local address the plugin is listening on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.config.local_addr()
    }

    /// Kill the plugin process.
    pub async fn kill(&mut self) -> io::Result<()> {
        self.child.kill().await
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        // Best-effort kill on drop
        let _ = self.child.start_kill();
    }
}
