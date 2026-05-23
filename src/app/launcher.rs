use std::sync::atomic::{AtomicU8, Ordering};
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LauncherIdentity {
    EdgeRay = 0,
    Compass = 1,
    Calculator = 2,
}

static CURRENT_IDENTITY: AtomicU8 = AtomicU8::new(0);

/// Sets the current launcher identity and notifies the platform layer.
pub fn set_identity(identity: LauncherIdentity) {
    CURRENT_IDENTITY.store(identity as u8, Ordering::SeqCst);
    info!("Launcher: Identity set to {:?}", identity);

    // Notify native layers via FFI callbacks or JNI
    #[cfg(target_os = "android")]
    crate::android::launcher::apply_identity(identity);

    #[cfg(target_os = "ios")]
    crate::ios::launcher::apply_identity(identity);
}

/// Returns the current active identity.
pub fn get_identity() -> LauncherIdentity {
    match CURRENT_IDENTITY.load(Ordering::Relaxed) {
        1 => LauncherIdentity::Compass,
        2 => LauncherIdentity::Calculator,
        _ => LauncherIdentity::EdgeRay,
    }
}

/// JNI / FFI hook for the platform to query the desired identity
#[unsafe(no_mangle)]
pub extern "C" fn rustray_get_launcher_identity() -> i32 {
    CURRENT_IDENTITY.load(Ordering::SeqCst) as i32
}
