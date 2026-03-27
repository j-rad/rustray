use crate::app::diagnostics::global_collector;
use actix_web::HttpResponse;
use std::io::{Cursor, Write};
use std::process::Command;
use zip::{ZipWriter, write::FileOptions};

pub async fn get_diagnostic_report() -> HttpResponse {
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    let mut zip = ZipWriter::new(&mut cursor);
    let options = FileOptions::<()>::default().compression_method(zip::CompressionMethod::Deflated);

    // 1. Logs
    let logs = global_collector().get_all();
    let mut log_content = String::new();
    for log in logs {
        log_content.push_str(&format!(
            "{} {} {}: {}\n",
            log.timestamp_str(),
            log.level.as_str(),
            log.target,
            log.message
        ));
    }

    // Simple Redaction
    let log_content = log_content.replace("private_key", "REDACTED_KEY");

    let _ = zip.start_file("rustray.log", options);
    let _ = zip.write_all(log_content.as_bytes());

    // 2. Output of uname -a
    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("uname").arg("-a").output() {
            let _ = zip.start_file("system_info.txt", options);
            let _ = zip.write_all(&output.stdout);
        }
    }

    // 3. NFTables
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("nft").args(["list", "ruleset"]).output() {
            let _ = zip.start_file("nftables.conf", options);
            let _ = zip.write_all(&output.stdout);
        }
    }

    let _ = zip.finish();

    HttpResponse::Ok()
        .content_type("application/zip")
        .insert_header((
            "Content-Disposition",
            "attachment; filename=\"diagnostic_report.zip\"",
        ))
        .body(buf)
}
