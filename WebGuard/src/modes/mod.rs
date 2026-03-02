//! Operational Modes for WebGuard
//!
//! Each mode provides a different way to integrate WebGuard with web infrastructure:
//!
//! ## Production Modes
//! - `proxy`: HTTP reverse proxy with inline analysis (recommended)
//! - `tail`: Real-time log file monitoring  
//! - `audit`: Batch log analysis for forensics
//!
//! ## Testing Only
//! - `demo`: Simulated telemetry for testing (NOT FOR PRODUCTION)
//!   Demo mode is implemented in main.rs using sensors::simulated

pub mod proxy;
pub mod tail;
pub mod audit;

pub use proxy::run_proxy_mode;
pub use tail::run_tail_mode;
pub use audit::run_audit_mode;
