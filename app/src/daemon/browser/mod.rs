//! Browser integration primitives; session handling lives in the daemon.

pub mod activity;
pub mod address;
pub mod auth;
#[cfg(test)]
mod auth_tests;
pub mod control;
pub mod dedupe;
pub mod dispatch;
#[cfg(test)]
mod dispatch_tests;
pub mod fill;
pub mod ids;
pub mod limits;
pub mod manifests;
pub mod pairing;
pub mod request;
pub mod save;
pub mod save_queue;
pub mod save_target;
pub mod session;
pub mod validation;
