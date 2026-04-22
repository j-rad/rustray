// src/app/platform_paths.rs
//! Platform-specific path resolution for mobile and desktop
//!
//! Ensures data is stored in the correct sandboxed location for each platform.

use std::env;
use std::path::PathBuf;

/// Get the platform-specific storage path for SurrealKV database
pub fn get_storage_path(app_id: &str) -> PathBuf {
    #[cfg(target_os = "ios")]
    {
        ios_group_container_path(app_id)
    }

    #[cfg(target_os = "android")]
    {
        android_files_dir(app_id)
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        desktop_config_dir(app_id)
    }
}

/// iOS App Group Container path
#[cfg(target_os = "ios")]
fn ios_group_container_path(app_id: &str) -> PathBuf {
    use std::ffi::CString;
    use std::os::raw::c_char;

    // In a real implementation, this would call iOS Foundation APIs
    // For now, return a placeholder path that follows iOS conventions
    let group_id = format!("group.{}", app_id);

    // iOS Group Container paths are typically:
    // /var/mobile/Containers/Shared/AppGroup/<UUID>
    // This requires calling FileManager.containerURL(forSecurityApplicationGroupIdentifier:)

    PathBuf::from(format!(
        "/var/mobile/Containers/Shared/AppGroup/{}/rustray.db",
        group_id
    ))
}

/// Android files directory path
#[cfg(target_os = "android")]
fn android_files_dir(app_id: &str) -> PathBuf {
    // Android internal storage: /data/data/<package>/files/
    // This requires calling Context.getFilesDir()

    PathBuf::from(format!("/data/data/{}/files/rustray.db", app_id))
}

/// Desktop configuration directory
#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn desktop_config_dir(app_id: &str) -> PathBuf {
    if let Some(mut config_dir) = dirs::config_dir() {
        config_dir.push(app_id);
        config_dir.push("rustray.db");
        config_dir
    } else {
        PathBuf::from("./rustray_data/rustray.db")
    }
}

/// Get the platform-specific log directory
pub fn get_log_path(app_id: &str) -> PathBuf {
    let mut storage_path = get_storage_path(app_id);
    storage_path.set_file_name("rustray.log");
    storage_path
}

/// Get the platform-specific directory for external binaries (RustRay/Sing-box)
pub fn get_bin_path(app_id: &str, core_name: &str) -> PathBuf {
    let mut storage_path = get_storage_path(app_id);
    storage_path.set_file_name("bin");
    let mut bin_dir = storage_path;
    if !bin_dir.exists() {
        let _ = std::fs::create_dir_all(&bin_dir);
    }

    #[cfg(target_os = "windows")]
    let filename = format!("{}.exe", core_name);
    #[cfg(not(target_os = "windows"))]
    let filename = core_name.to_string();

    bin_dir.push(filename);
    bin_dir
}

/// Get the platform-specific directory for assets (.dat files)
pub fn get_asset_dir(app_id: &str) -> PathBuf {
    // Allow overriding via environment variable for testing
    if let Ok(dir) = env::var("RUSTRAY_ASSET_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(target_os = "ios")]
    {
        // On iOS, assets might be in the bundle or Documents.
        // For dynamic updates, use Documents/Library.
        let mut path = ios_group_container_path(app_id);
        path.pop(); // Remove rustray.db
        path.push("assets");
        path
    }

    #[cfg(target_os = "android")]
    {
        let mut path = android_files_dir(app_id);
        path.pop();
        path.push("assets");
        path
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        // Use a writable directory next to config/db
        let mut path = desktop_config_dir(app_id);
        path.pop(); // Remove rustray.db
        path.push("assets");
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_path_not_empty() {
        let path = get_storage_path("com.example.test");
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_log_path_has_log_extension() {
        let path = get_log_path("com.example.test");
        assert_eq!(path.extension().unwrap(), "log");
    }

    #[test]
    fn test_asset_dir() {
        let path = get_asset_dir("com.example.test");
        assert!(path.ends_with("assets"));
    }

    #[test]
    fn test_asset_dir_env_override() {
        unsafe { env::set_var("RUSTRAY_ASSET_DIR", "/tmp/test_assets") };
        let path = get_asset_dir("com.example.test");
        assert_eq!(path, PathBuf::from("/tmp/test_assets"));
        unsafe { env::remove_var("RUSTRAY_ASSET_DIR") };
    }
}
