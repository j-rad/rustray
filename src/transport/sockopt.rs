// src/transport/sockopt.rs
use crate::config::{CustomSockopt, Sockopt};
use crate::error::Result;
use socket2::{Socket, TcpKeepalive};
use std::time::Duration;
use tracing::warn;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

pub fn apply_sockopt(socket: &Socket, settings: &Sockopt) -> Result<()> {
    if let Some(mark) = settings.mark {
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = socket.set_mark(mark as u32) {
                warn!("Failed to set SO_MARK: {}", e);
            }
        }
        #[cfg(not(target_os = "linux"))]
        warn!("SO_MARK is only supported on Linux");
    }

    if let Some(mss) = settings.tcp_max_seg {
        if let Err(e) = socket.set_mss(mss as u32) {
            warn!("Failed to set TCP_MAXSEG: {}", e);
        }
    }

    if let Some(ref tfo) = settings.tcp_fast_open {
        let val = if tfo.is_boolean() {
            if tfo.as_bool().unwrap() { 256 } else { -1 }
        } else {
            tfo.as_i64().unwrap_or(0) as i32
        };

        if val >= 0 {
            #[cfg(target_os = "linux")]
            {
                // socket2 set_tcp_fastopen is for listener. For outbound it's different?
                // Actually TCP_FASTOPEN_CONNECT is for outbound.
                unsafe {
                    let optval: libc::c_int = 1;
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        libc::TCP_FASTOPEN_CONNECT,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&optval) as libc::socklen_t,
                    );
                }
            }
        }
    }

    if let Some(ref tproxy) = settings.tproxy {
        if tproxy == "tproxy" || tproxy == "redirect" {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = socket.set_ip_transparent(true) {
                    warn!("Failed to set IP_TRANSPARENT: {}", e);
                }
            }
        }
    }

    let mut keepalive = TcpKeepalive::new();
    let mut ka_set = false;

    if let Some(idle) = settings.tcp_keep_alive_idle {
        if idle > 0 {
            keepalive = keepalive.with_time(Duration::from_secs(idle as u64));
            ka_set = true;
        }
    }

    if let Some(interval) = settings.tcp_keep_alive_interval {
        if interval > 0 {
            keepalive = keepalive.with_interval(Duration::from_secs(interval as u64));
            ka_set = true;
        }
    }

    if ka_set {
        if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
            warn!("Failed to set TCP Keepalive: {}", e);
        }
    }

    if let Some(timeout) = settings.tcp_user_timeout {
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = socket.set_tcp_user_timeout(Some(Duration::from_millis(timeout as u64))) {
                warn!("Failed to set TCP_USER_TIMEOUT: {}", e);
            }
        }
    }

    if let Some(ref congestion) = settings.tcpcongestion {
        #[cfg(target_os = "linux")]
        {
            // socket2 doesn't have set_tcp_congestion yet, use setsockopt
            unsafe {
                let bytes = congestion.as_bytes();
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    bytes.as_ptr() as *const libc::c_void,
                    bytes.len() as libc::socklen_t,
                );
            }
        }
    }

    if let Some(ref interface) = settings.r#interface {
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = socket.bind_device(Some(interface.as_bytes())) {
                warn!("Failed to bind to interface {}: {}", interface, e);
            }
        }
    }

    if let Some(v6only) = settings.v6_only {
        if let Err(e) = socket.set_only_v6(v6only) {
            warn!("Failed to set IPV6_V6ONLY: {}", e);
        }
    }

    if let Some(clamp) = settings.tcp_window_clamp {
        #[cfg(target_os = "linux")]
        unsafe {
            let optval: libc::c_int = clamp;
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
        }
    }

    if let Some(ref custom) = settings.custom_sockopt {
        for opt in custom {
            apply_custom_sockopt(socket, opt)?;
        }
    }

    Ok(())
}

fn apply_custom_sockopt(socket: &Socket, opt: &CustomSockopt) -> Result<()> {
    let current_system = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        "darwin"
    } else {
        "unknown"
    };

    if let Some(ref sys) = opt.system {
        if sys != current_system {
            return Ok(());
        }
    }

    let level: i32 = opt.level.as_ref().and_then(|l| l.parse().ok()).unwrap_or(6); // Default 6 is TCP
    let option_num: i32 = opt.opt.parse().map_err(|_| anyhow::anyhow!("Invalid custom sockopt opt: {}", opt.opt))?;

    match opt.r#type.as_str() {
        "int" => {
            let val: i32 = opt.value.parse().map_err(|_| anyhow::anyhow!("Invalid custom sockopt value: {}", opt.value))?;
            unsafe {
                #[cfg(unix)]
                let fd = socket.as_raw_fd();
                #[cfg(windows)]
                let fd = socket.as_raw_socket() as i32;

                libc::setsockopt(
                    fd as _,
                    level,
                    option_num,
                    &val as *const _ as *const _,
                    std::mem::size_of_val(&val) as _,
                );
            }
        }
        "str" => {
            let val = opt.value.as_bytes();
            unsafe {
                #[cfg(unix)]
                let fd = socket.as_raw_fd();
                #[cfg(windows)]
                let fd = socket.as_raw_socket() as i32;

                libc::setsockopt(
                    fd as _,
                    level,
                    option_num,
                    val.as_ptr() as *const _,
                    val.len() as _,
                );
            }
        }
        _ => warn!("Unsupported custom sockopt type: {}", opt.r#type),
    }

    Ok(())
}
