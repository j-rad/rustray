#[cfg(feature = "tonic")]
pub mod handler;
#[cfg(feature = "tonic")]
pub mod server;
pub mod signaling;
#[cfg(feature = "tonic")]
pub mod stats;

#[cfg(feature = "minimal-server")]
pub mod headless;

#[cfg(feature = "minimal-server")]
pub mod embedded_assets;

#[cfg(feature = "minimal-server")]
pub mod auth_middleware;

#[cfg(feature = "minimal-server")]
pub mod diagnostics_api;

#[cfg(feature = "minimal-server")]
pub mod speedtest_api;

#[cfg(feature = "full-server")]
pub mod users;

#[cfg(feature = "full-server")]
pub mod audit_middleware;

// Generated proto modules from tonic-build
#[cfg(feature = "tonic")]
pub mod xray {
    pub mod common {
        pub mod serial {
            tonic::include_proto!("xray.common.serial");
        }
        pub mod net {
            tonic::include_proto!("xray.common.net");
        }
        pub mod protocol {
            tonic::include_proto!("xray.common.protocol");
        }
    }

    pub mod core {
        tonic::include_proto!("xray.core");
    }

    pub mod app {
        pub mod proxyman {
            pub mod command {
                tonic::include_proto!("xray.app.proxyman.command");
            }
        }
        pub mod stats {
            pub mod command {
                tonic::include_proto!("xray.app.stats.command");
            }
        }
    }

    pub mod proxy {
        pub mod vless {
            tonic::include_proto!("xray.proxy.vless");
        }
        pub mod vmess {
            tonic::include_proto!("xray.proxy.vmess");
        }
        pub mod trojan {
            tonic::include_proto!("xray.proxy.trojan");
        }
    }
}
