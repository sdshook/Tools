
use anyhow::Result;
use tracing::info;
use std::fs::OpenOptions;
use std::io::Write;

pub async fn snapshot_evidence(pid: i32, reason: &str) -> Result<()> {
    info!( "Snapshot evidence pid={} reason={}", pid, reason );
    let mut f = OpenOptions::new().create(true).append(true).open("evidence.log")?;
    let line = format!(r#"{{"pid":{},"reason":"{}","time":{}}}\n"#, pid, reason, chrono::Utc::now().timestamp());
    f.write_all(line.as_bytes())?;
    Ok(())
}
