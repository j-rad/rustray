//! Integration Tests for Embedded Assets and Headless Server
//!
//! Tests the embedded dashboard serving alongside the PSK-protected API endpoints.

#[cfg(feature = "minimal-server")]
mod embedded_tests {
    use actix_web::{App, http::StatusCode, test, web};
    use rustray::api::headless::{
        HeadlessState, PskMiddleware, apply_config, get_stats, health_check, serve_index,
        serve_static_asset,
    };
    use rustray::ffi::EngineManager;

    /// Helper to create test app with all routes
    async fn create_test_app() -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    > {
        let engine = EngineManager::new();
        let psk = "test-psk-12345".to_string();
        let state = web::Data::new(HeadlessState {
            psk: psk.clone(),
            engine,
        });

        test::init_service(
            App::new()
                .wrap(PskMiddleware { psk: psk.clone() })
                .app_data(state.clone())
                .route("/health", web::get().to(health_check))
                .route("/node/apply", web::post().to(apply_config))
                .route("/node/stats", web::get().to(get_stats))
                .route("/", web::get().to(serve_index))
                .route("/{path:.*}", web::get().to(serve_static_asset)),
        )
        .await
    }

    /// Test: Health endpoint is accessible without authentication
    #[actix_web::test]
    async fn test_health_check_no_auth() {
        let app = create_test_app().await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "healthy");
        assert!(body["version"].as_str().is_some());
    }

    /// Test: API endpoints require PSK authentication
    #[actix_web::test]
    async fn test_api_requires_psk() {
        let app = create_test_app().await;

        // Without PSK header
        let req = test::TestRequest::get().uri("/node/stats").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With wrong PSK
        let req = test::TestRequest::get()
            .uri("/node/stats")
            .insert_header(("X-RUSTRAY-PSK", "wrong-psk"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With correct PSK
        let req = test::TestRequest::get()
            .uri("/node/stats")
            .insert_header(("X-RUSTRAY-PSK", "test-psk-12345"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Test: Static assets are served without authentication
    #[actix_web::test]
    async fn test_static_assets_no_auth() {
        let app = create_test_app().await;

        // Root should not require auth
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;

        // Should return 200 (with index.html) or 503 (if no assets embedded)
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Test: List embedded assets (development helper)
    #[test]
    async fn test_list_embedded_assets() {
        let assets = rustray::api::embedded_assets::list_assets();

        // In test environment, we may or may not have assets
        // This test ensures the function doesn't panic
        println!("Embedded assets count: {}", assets.len());
        for asset in assets.iter().take(10) {
            println!("  - {}", asset);
        }
    }

    /// Test: SPA fallback for unknown paths
    #[actix_web::test]
    async fn test_spa_fallback() {
        let app = create_test_app().await;

        // Unknown path should fallback to index.html (SPA routing)
        let req = test::TestRequest::get()
            .uri("/dashboard/settings")
            .to_request();
        let resp = test::call_service(&app, req).await;

        // Should return 200 with index.html or 404 if no assets
        // The key is it should NOT return UNAUTHORIZED
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Test: Gzip content encoding negotiation
    #[actix_web::test]
    async fn test_gzip_negotiation() {
        let app = create_test_app().await;

        // Request with Accept-Encoding: gzip
        let req = test::TestRequest::get()
            .uri("/")
            .insert_header(("Accept-Encoding", "gzip, deflate"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        // If assets are present and gzipped, should have Content-Encoding header
        // This test just ensures the header parsing doesn't break
        let _content_encoding = resp.headers().get("Content-Encoding");
        // Header may or may not be present depending on whether .gz files exist
    }

    /// Test: Stats endpoint returns valid JSON
    #[actix_web::test]
    async fn test_stats_json_format() {
        let app = create_test_app().await;

        let req = test::TestRequest::get()
            .uri("/node/stats")
            .insert_header(("X-RUSTRAY-PSK", "test-psk-12345"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;

        // Verify expected fields in stats response
        assert!(body.get("bytes_uploaded").is_some());
        assert!(body.get("bytes_downloaded").is_some());
        assert!(body.get("connection_state").is_some());
    }

    /// Test: Apply config with invalid JSON returns error
    #[actix_web::test]
    async fn test_apply_invalid_config() {
        let app = create_test_app().await;

        let req = test::TestRequest::post()
            .uri("/node/apply")
            .insert_header(("X-RUSTRAY-PSK", "test-psk-12345"))
            .set_json(serde_json::json!({
                "invalid": "config"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
