// build.rs
/// This script runs at build time to compile all gRPC definitions
/// into Rust code for RustRay compatibility.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");

    // Ensure proto directory exists
    let proto_root = std::path::Path::new("proto");
    if !proto_root.exists() {
        panic!("The 'proto' directory was not found at root. Please ensure it exists.");
    }

    // List of RustRay proto files to compile
    // These are the core proto files needed for gRPC API compatibility with rr-ui
    let rustray_protos = vec![
        "proto/common.proto",
        "proto/common_serial.proto",
        "proto/common_protocol.proto",
        "proto/rustray.proto",
        "proto/stats.proto",
        "proto/proxyman.proto",
    ];

    // Verify all proto files exist
    for proto_file in &rustray_protos {
        let path = std::path::Path::new(proto_file);
        if !path.exists() {
            panic!("Required proto file not found: {}", proto_file);
        }
    }

    // Use tonic-build to compile the RustRay proto files
    tonic_build::configure()
        .build_server(true) // Build server implementations for gRPC services
        .build_client(true) // We are the server, not the client
        .compile_protos(&rustray_protos, &["proto"])?;

    Ok(())
}
