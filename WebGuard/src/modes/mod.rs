//! Operational Modes for WebGuard
//!
//! Each mode provides a different way to integrate WebGuard with web infrastructure:
//! - `proxy`: HTTP reverse proxy with inline analysis
//! - `tail`: Real-time log file monitoring  
//! - `audit`: Batch log analysis for forensics
//! - `simulate`: Simulated telemetry for testing

pub mod proxy;
pub mod tail;
pub mod audit;

pub use proxy::run_proxy_mode;
pub use tail::run_tail_mode;
pub use audit::run_audit_mode;
