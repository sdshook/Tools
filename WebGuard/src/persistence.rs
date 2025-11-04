
use anyhow::Result;
use tracing::info;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use serde_json::json;

pub fn persist() -> Result<()> {
    info!( "Persisting memory engine (stub)" );
    create_dir_all("./data")?;
    let fpath = "./data/persist_snapshot.json";
    let mut f = File::create(fpath)?;
    let meta = json!({"ts": chrono::Utc::now().to_rfc3339()});
    f.write_all(serde_json::to_string_pretty(&meta).unwrap().as_bytes())?;
    Ok(())
}
