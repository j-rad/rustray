#[cfg(feature = "minimal-server")]
mod headless_tests {
    use actix_web::{App, test, web};
    use rustray::api::headless::{HeadlessState, PskMiddleware, apply_config, get_stats};
    use rustray::ffi::EngineManager;
    

    /// Test Headless API PSK Auth and Stats
    #[actix_web::test]
    async fn test_headless_auth_and_stats() {
        let engine = EngineManager::new();
        let psk = "secret123".to_string();
        let state = web::Data::new(HeadlessState {
            psk: psk.clone(),
            engine,
        });

        let app = test::init_service(
            App::new()
                .wrap(PskMiddleware { psk: psk.clone() })
                .app_data(state.clone())
                .route("/node/apply", web::post().to(apply_config))
                .route("/node/stats", web::get().to(get_stats)),
        )
        .await;

        // 1. Success Case
        let req = test::TestRequest::get()
            .uri("/node/stats")
            .insert_header(("X-RUSTRAY-PSK", "secret123"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // 2. Auth Failure (Wrong PSK)
        let req = test::TestRequest::get()
            .uri("/node/stats")
            .insert_header(("X-RUSTRAY-PSK", "wrong"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);

        // 3. Auth Failure (No Header)
        let req = test::TestRequest::get().uri("/node/stats").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    /// Test Configuration Apply
    #[actix_web::test]
    async fn test_apply_config() {
        let engine = EngineManager::new();
        let psk = "secret123".to_string();
        let state = web::Data::new(HeadlessState {
            psk: psk.clone(),
            engine,
        });

        let app = test::init_service(
            App::new()
                .wrap(PskMiddleware { psk: psk.clone() })
                .app_data(state.clone())
                .route("/node/apply", web::post().to(apply_config)),
        )
        .await;

        // Invalid Config should return Bad Request
        let req = test::TestRequest::post()
            .uri("/node/apply")
            .insert_header(("X-RUSTRAY-PSK", "secret123"))
            .set_json(serde_json::json!({
                "address": "127.0.0.1",
                "missing": "fields"
            }))
            .to_request();

        // Note: Our FFI parser is robust but invalid JSON structure for ConnectConfig should fail.
        // ConnectConfig has required fields like 'port', 'uuid'.
        let resp = test::call_service(&app, req).await;
        // The handler calls start_engine, which parses config. If parsing fails, it returns ConfigError.
        // Handler maps ConfigError to BadRequest.
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }
}
