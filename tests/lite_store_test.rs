// tests/lite_store_test.rs
//! integration test for LiteStore (Phase 4)

#[cfg(not(feature = "surrealdb"))]
#[test]
fn test_lite_store_persistence() {
    use rustray::db::LiteStore;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use tempfile::NamedTempFile;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        name: String,
        value: i32,
    }

    // 1. Create a temp file path
    let tmp_file = NamedTempFile::new().unwrap();
    let path = tmp_file.path().to_str().unwrap().to_string();
    // Close the file so LiteStore can use the path (LiteStore expects a path)
    // Actually NamedTempFile deletes on drop. We want a persistent path for the test duration.
    // Let's use a temp dir.
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("lite.json");
    let db_path_str = db_path.to_str().unwrap();

    // 2. Initialize LiteStore (should be empty)
    let store = LiteStore::new(db_path_str);

    // 3. Write data
    let data = TestData {
        name: "test".to_string(),
        value: 42,
    };
    store.set("key1", &data).expect("Failed to set key");

    // 4. Read back immediate
    let loaded: TestData = store.get("key1").expect("Failed to get key");
    assert_eq!(loaded, data);

    // 5. Reload store from disk
    drop(store);
    let store2 = LiteStore::new(db_path_str);
    let reloaded: TestData = store2.get("key1").expect("Failed to get key after reload");
    assert_eq!(reloaded, data);

    // 6. Delete
    store2.delete("key1").expect("Failed to delete");
    let missing: Option<TestData> = store2.get("key1");
    assert!(missing.is_none());
}
