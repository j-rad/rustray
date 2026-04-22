// src/api/mod.rs

pub mod server;
pub mod handler;
pub mod stats;
pub mod signaling;
pub mod users;
pub mod auth_middleware;
pub mod audit_middleware;
pub mod diagnostics_api;
pub mod speedtest_api;
pub mod headless;
pub mod embedded_assets;
pub mod handlers;

pub mod rustray {
    pub mod core {
        tonic::include_proto!("rustray.core");
    }

    pub mod common {
        pub mod net {
            tonic::include_proto!("rustray.common.net");
        }
        pub mod protocol {
            tonic::include_proto!("rustray.common.protocol");
        }
        pub mod serial {
            tonic::include_proto!("rustray.common.serial");
        }
    }

    pub mod app {
        pub mod proxyman {
            pub mod command {
                tonic::include_proto!("rustray.app.proxyman.command");
            }
        }
        pub mod stats {
            pub mod command {
                tonic::include_proto!("rustray.app.stats.command");
            }
        }
        pub mod router {
            pub mod command {
                tonic::include_proto!("rustray.app.router.command");
            }
        }
        pub mod log {
            pub mod command {
                tonic::include_proto!("rustray.app.log.command");
            }
        }
        pub mod observatory {
            pub mod command {
                tonic::include_proto!("rustray.app.observatory.command");
            }
        }
    }

    pub mod transport {
        pub mod internet {
            tonic::include_proto!("rustray.transport.internet");
            pub mod reality {
                tonic::include_proto!("rustray.transport.internet.reality");
            }
        }
    }

    pub mod proxy {
        pub mod vless {
            tonic::include_proto!("rustray.proxy.vless");
        }
        pub mod vmess {
            tonic::include_proto!("rustray.proxy.vmess");
        }
        pub mod trojan {
            tonic::include_proto!("rustray.proxy.trojan");
        }
        pub mod flow_j {
            tonic::include_proto!("rustray.proxy.flow_j");
        }
        pub mod hysteria2 {
            tonic::include_proto!("rustray.proxy.hysteria2");
        }
        pub mod tuic {
            tonic::include_proto!("rustray.proxy.tuic");
        }
        pub mod wireguard {
            tonic::include_proto!("rustray.proxy.wireguard");
        }
        pub mod warp {
            tonic::include_proto!("rustray.proxy.warp");
        }
    }
}
