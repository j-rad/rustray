// src/android/jni.rs
//! JNI bridge for Android VpnService socket protection
//!
//! This module provides the critical functionality to protect outbound proxy sockets
//! from being routed through the TUN interface, preventing VPN routing loops.

use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tracing::{debug, warn};

/// Global flag indicating if we're running on Android
static IS_ANDROID: AtomicBool = AtomicBool::new(false);

/// Thread-safe callback function pointer for socket protection
static PROTECT_CALLBACK: OnceLock<fn(i32) -> bool> = OnceLock::new();

/// Initialize the Android JNI bridge with a protect callback
///
/// This must be called from the Android app during initialization.
/// Thread-safe and can only be called once.
pub fn init_android_bridge(protect_fn: fn(i32) -> bool) {
    if PROTECT_CALLBACK.set(protect_fn).is_err() {
        warn!("Android JNI bridge already initialized, ignoring duplicate call");
        return;
    }
    IS_ANDROID.store(true, Ordering::Release);
    debug!("Android JNI bridge initialized");
}

/// Check if running on Android platform
#[inline]
pub fn is_android() -> bool {
    IS_ANDROID.load(Ordering::Acquire)
}

/// Protect a socket from VPN routing
///
/// Calls the Android VpnService.protect() method via JNI callback
/// Returns true if protection succeeded, false otherwise
pub fn protect_socket<S: AsRawFd>(socket: &S) -> bool {
    if !is_android() {
        // Not on Android, no protection needed
        return true;
    }

    let fd = socket.as_raw_fd();

    if let Some(protect_fn) = PROTECT_CALLBACK.get() {
        let result = protect_fn(fd);
        if result {
            debug!("Socket fd={} protected successfully", fd);
        } else {
            warn!("Failed to protect socket fd={}", fd);
        }
        result
    } else {
        warn!("Android protect callback not initialized!");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_android_default() {
        assert!(!is_android());
    }

    #[test]
    fn test_protect_socket_non_android() {
        use std::net::TcpStream;
        let socket = TcpStream::connect("1.1.1.1:80");
        if let Ok(s) = socket {
            // Should return true on non-Android platforms
            assert!(protect_socket(&s));
        }
    }
}

// ============================================================================
// JNI EXPORTS FOR ANDROID
// ============================================================================

#[cfg(target_os = "android")]
mod jni_exports {
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
    use jni::JNIEnv;
    use std::ffi::CStr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::runtime::Runtime;
    use tracing::{error, info};

    use crate::ffi::{global_shared_stats, ConnectConfig, EngineManager};

    /// Global engine instance for JNI
    static JNI_ENGINE: OnceLock<Arc<EngineManager>> = OnceLock::new();
    static JNI_RUNTIME: OnceLock<Runtime> = OnceLock::new();
    static VPN_RUNNING: AtomicBool = AtomicBool::new(false);

    /// Protect callback holder for VpnService.protect()
    static PROTECT_FN: OnceLock<Mutex<Option<Box<dyn Fn(i32) -> bool + Send + Sync>>>> =
        OnceLock::new();

    fn get_engine() -> Arc<EngineManager> {
        JNI_ENGINE.get_or_init(|| EngineManager::new()).clone()
    }

    fn get_runtime() -> &'static Runtime {
        JNI_RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create Tokio runtime for JNI"))
    }

    /// JNI: Start VPN with TUN file descriptor
    ///
    /// # Safety
    /// Called from JNI - must handle all errors gracefully
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_jrad_edgeray_1app_EdgeRayVpnService_nativeStartVpnWithFd(
        mut env: JNIEnv,
        _class: JClass,
        fd: jint,
        config_json: JString,
    ) -> jint {
        let config_str = match env.get_string(&config_json) {
            Ok(s) => s.to_string_lossy().into_owned(),
            Err(e) => {
                error!("JNI: Failed to get config string: {}", e);
                return -1;
            }
        };

        info!(
            "JNI: Starting VPN with FD={}, config_len={}",
            fd,
            config_str.len()
        );

        // Inject the TUN FD into the config
        let mut connect_config: ConnectConfig = match serde_json::from_str(&config_str) {
            Ok(c) => c,
            Err(e) => {
                error!("JNI: Failed to parse config: {}", e);
                return -2;
            }
        };
        connect_config.tun_fd = Some(fd);

        let config_with_fd = match serde_json::to_string(&connect_config) {
            Ok(s) => s,
            Err(e) => {
                error!("JNI: Failed to serialize config: {}", e);
                return -3;
            }
        };

        let engine = get_engine();

        // Create a VPN callback that calls back to Java for socket protection
        // For now we use None as the callback is handled separately
        match engine.start_engine(config_with_fd, None) {
            crate::ffi::RustRayResult::Ok => {
                VPN_RUNNING.store(true, Ordering::Release);
                info!("JNI: VPN engine started successfully");
                0
            }
            crate::ffi::RustRayResult::AlreadyRunning => {
                info!("JNI: VPN engine already running");
                0
            }
            crate::ffi::RustRayResult::ConfigError(e) => {
                error!("JNI: Config error: {}", e);
                -4
            }
            crate::ffi::RustRayResult::ConnectionError(e) => {
                error!("JNI: Connection error: {}", e);
                -5
            }
            other => {
                error!("JNI: Engine start failed: {:?}", other);
                -6
            }
        }
    }

    /// JNI: Stop VPN
    ///
    /// # Safety
    /// Called from JNI
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_jrad_edgeray_1app_EdgeRayVpnService_nativeStopVpn(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        info!("JNI: Stopping VPN engine");

        let engine = get_engine();
        match engine.stop_engine() {
            crate::ffi::RustRayResult::Ok => {
                VPN_RUNNING.store(false, Ordering::Release);
                info!("JNI: VPN engine stopped successfully");
                0
            }
            crate::ffi::RustRayResult::NotRunning => {
                info!("JNI: VPN engine was not running");
                0
            }
            other => {
                error!("JNI: Engine stop failed: {:?}", other);
                -1
            }
        }
    }

    /// JNI: Get metrics as JSON string
    ///
    /// # Safety
    /// Called from JNI
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_jrad_edgeray_1app_EdgeRayVpnService_nativeGetMetricsJson<
        'a,
    >(
        mut env: JNIEnv<'a>,
        _class: JClass<'a>,
    ) -> JString<'a> {
        let engine = get_engine();
        let json = engine.get_stats_json();

        match env.new_string(&json) {
            Ok(s) => s,
            Err(e) => {
                error!("JNI: Failed to create metrics string: {}", e);
                env.new_string("{}").unwrap_or_else(|_| JString::default())
            }
        }
    }

    /// JNI: Protect a socket (called from Rust back to Java)
    ///
    /// # Safety
    /// Called from JNI
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_jrad_edgeray_1app_EdgeRayVpnService_nativeProtectSocket(
        _env: JNIEnv,
        _class: JClass,
        fd: jint,
    ) -> jboolean {
        // This is called TO protect a socket, but we actually need to call
        // back to Java's VpnService.protect(). For now, use the callback.
        if let Some(protect_mutex) = PROTECT_FN.get() {
            if let Ok(guard) = protect_mutex.lock() {
                if let Some(ref protect_fn) = *guard {
                    return if protect_fn(fd) { JNI_TRUE } else { JNI_FALSE };
                }
            }
        }
        JNI_FALSE
    }

    /// JNI: Get metrics (for QS Tile - same as EdgeRayVpnService)
    ///
    /// # Safety
    /// Called from JNI
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_jrad_edgeray_1app_EdgeRayQSTile_nativeGetMetricsJson<
        'a,
    >(
        mut env: JNIEnv<'a>,
        _class: JClass<'a>,
    ) -> JString<'a> {
        let engine = get_engine();
        let json = engine.get_stats_json();

        match env.new_string(&json) {
            Ok(s) => s,
            Err(e) => {
                error!("JNI: Failed to create metrics string for QS Tile: {}", e);
                env.new_string("{}").unwrap_or_else(|_| JString::default())
            }
        }
    }
}
