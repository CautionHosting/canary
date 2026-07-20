//! Phase 2 Canary monitor service library.
//!
//! Runtime wiring is added after the pure state, probe, and persistence
//! boundaries are independently verified.

pub mod api;
pub mod html;
pub mod metadata;
pub mod model;
pub mod network;
pub mod probe;
pub mod runtime;
pub mod scheduler;
pub mod store;
