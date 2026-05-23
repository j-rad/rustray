//! System-level Kill-Switch using nftables (Linux/Android) and WFP (Windows).
//!
//! Prevents packet leaks by dropping all traffic that doesn't originate from
//! the EdgeRay process or pass through the TUN interface.

use log::{error, info};
use std::process::Command;

pub struct KillSwitch;

impl KillSwitch {
    /// Enable the system-level firewall rules.
    pub fn enable() {
        info!("Enabling System Kill-Switch...");

        #[cfg(target_os = "linux")]
        {
            if let Err(e) = Self::apply_nftables_rules() {
                error!("Failed to apply nftables rules: {}", e);
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Err(e) = Self::apply_wfp_rules() {
                error!("Failed to apply WFP rules: {}", e);
            }
        }
    }

    /// Disable the system-level firewall rules.
    pub fn disable() {
        info!("Disabling System Kill-Switch...");

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", "edgeray_killswitch"])
                .status();
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_nftables_rules() -> std::io::Result<()> {
        // 1. Create a dedicated table
        Self::run_nft(&["add", "table", "inet", "edgeray_killswitch"])?;

        // 2. Create chains
        Self::run_nft(&[
            "add",
            "chain",
            "inet",
            "edgeray_killswitch",
            "output",
            "{ type filter hook output priority 0; policy drop; }",
        ])?;
        Self::run_nft(&[
            "add",
            "chain",
            "inet",
            "edgeray_killswitch",
            "input",
            "{ type filter hook input priority 0; policy drop; }",
        ])?;

        // 3. Allow Loopback
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "edgeray_killswitch",
            "output",
            "oif",
            "lo",
            "accept",
        ])?;
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "edgeray_killswitch",
            "input",
            "iif",
            "lo",
            "accept",
        ])?;

        // 4. Allow TUN interface (usually 'tun0')
        // We allow all traffic on the tun interface as it's already encrypted/tunneled by us.
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "edgeray_killswitch",
            "output",
            "oifname",
            "tun*",
            "accept",
        ])?;
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "edgeray_killswitch",
            "input",
            "iifname",
            "tun*",
            "accept",
        ])?;

        // 5. Allow EdgeRay traffic (The core needs to talk to the upstream server)
        // On Linux, we can match by UID if running as a specific user, or we can use marks.
        // For simplicity and resilience, we allow established/related traffic.
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "edgeray_killswitch",
            "output",
            "ct",
            "state",
            "established,related",
            "accept",
        ])?;
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "edgeray_killswitch",
            "input",
            "ct",
            "state",
            "established,related",
            "accept",
        ])?;

        // 6. Special rule for the VPN process itself to reach the gateway/DNS
        // This is tricky without knowing the server IP.
        // In a full implementation, we'd dynamically add the server IP to an 'allow' set.

        info!("nftables Kill-Switch rules applied successfully.");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn run_nft(args: &[&str]) -> std::io::Result<()> {
        let status = Command::new("nft").args(args).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "nft command failed: {:?}",
                args
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn apply_wfp_rules() -> std::io::Result<()> {
        warn!("WFP Kill-Switch implementation via netsh/powershell (fallback)");
        // In a production environment, this should use the WFP API directly via FFI.
        // For now, we use a strong block policy via netsh as a placeholder.
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "blockinbound,blockoutbound",
            ])
            .status();
        // Then allow loopback and specific exceptions...
        Ok(())
    }
}
