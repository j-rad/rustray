//! Embedded Static Assets for Headless Dashboard
//!
//! This module provides the embedded Wasm dashboard assets for the headless server.
//! Assets are compiled from edgeray-app and embedded at compile time using rust-embed.
//!
//! Features:
//! - Automatic MIME type detection
//! - Gzip content-encoding negotiation
//! - Immutable cache headers for hashed assets
//! - SPA fallback to index.html for client-side routing

#[cfg(feature = "minimal-server")]
use rust_embed::{Embed, RustEmbed};

/// Embedded static assets from the edgeray-app Wasm build.
/// The folder path is relative to the rustray crate root.
#[derive(RustEmbed)]
#[folder = "assets/"]
#[prefix = ""]
#[cfg(feature = "minimal-server")]
pub struct EmbeddedAssets;

#[cfg(feature = "minimal-server")]
use actix_web::{HttpRequest, HttpResponse, http::header};

/// Serve an embedded asset with proper MIME type and caching headers.
/// Supports gzip content-encoding negotiation.
#[cfg(feature = "minimal-server")]
pub fn serve_asset(req: &HttpRequest, path: &str) -> Option<HttpResponse> {
    let accepts_gzip = req
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("gzip"))
        .unwrap_or(false);

    // Try gzipped version first if client accepts it
    let (content, is_gzipped) = if accepts_gzip {
        let gz_path = format!("{}.gz", path);
        if let Some(asset) = EmbeddedAssets::get(&gz_path) {
            (Some(asset), true)
        } else {
            (EmbeddedAssets::get(path), false)
        }
    } else {
        (EmbeddedAssets::get(path), false)
    };

    let asset = content?;

    // Determine MIME type from original path (not .gz)
    let mime_type = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();

    // Build response with appropriate headers
    let mut response = HttpResponse::Ok();
    response.insert_header((header::CONTENT_TYPE, mime_type));

    // Add gzip encoding header if serving compressed content
    if is_gzipped {
        response.insert_header((header::CONTENT_ENCODING, "gzip"));
    }

    // Cache control: immutable for hashed assets, short cache for others
    let cache_control = if path.contains('.') && is_hashed_filename(path) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };
    response.insert_header((header::CACHE_CONTROL, cache_control));

    // ETag based on embedded hash
    let etag = format!("\"{}\"", base64_hash(&asset.data));
    response.insert_header((header::ETAG, etag));

    Some(response.body(asset.data.into_owned()))
}

/// Check if a filename appears to contain a content hash (e.g., app-3a7b2c1d.js)
#[cfg(feature = "minimal-server")]
fn is_hashed_filename(path: &str) -> bool {
    // Look for pattern: name-[hash].ext where hash is 8+ hex chars
    if let Some(stem) = path.rsplit('/').next() {
        if let Some((name_part, _ext)) = stem.rsplit_once('.') {
            if let Some((_, hash)) = name_part.rsplit_once('-') {
                return hash.len() >= 8 && hash.chars().all(|c| c.is_ascii_hexdigit());
            }
        }
    }
    false
}

/// Generate a short base64 hash for ETag
#[cfg(feature = "minimal-server")]
fn base64_hash(data: &[u8]) -> String {
    use base64::Engine;
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();
    base64::engine::general_purpose::STANDARD.encode(&hash.to_le_bytes())[..11].to_string()
}

/// Get the index.html content for SPA fallback
#[cfg(feature = "minimal-server")]
pub fn get_index_html() -> Option<Vec<u8>> {
    EmbeddedAssets::get("index.html").map(|a| a.data.into_owned())
}

/// List all embedded asset paths (for debugging/testing)
#[cfg(feature = "minimal-server")]
pub fn list_assets() -> Vec<String> {
    EmbeddedAssets::iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
#[cfg(feature = "minimal-server")]
mod tests {
    use super::*;

    #[test]
    fn test_is_hashed_filename() {
        assert!(is_hashed_filename("app-3a7b2c1d.js"));
        assert!(is_hashed_filename("styles-abcdef12.css"));
        assert!(is_hashed_filename("assets/chunk-12345678.wasm"));
        assert!(!is_hashed_filename("index.html"));
        assert!(!is_hashed_filename("styles.css"));
        assert!(!is_hashed_filename("app-abc.js")); // hash too short
    }
}
