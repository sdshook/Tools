
#[cfg(target_os = "linux")]
use anyhow::Result;
use tracing::info;

pub async fn apply_nginx_mitigation(pid: i32, action: &str) -> Result<()> {
    info!( "NGINX mitigation pid={} action={}", pid, action );
    Ok(())
}
