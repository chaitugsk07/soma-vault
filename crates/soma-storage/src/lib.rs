#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

//! Data layer for soma-vault: `DataStore` trait + `PgDataStore` (sqlx/Postgres).

/// Error types for `soma-storage`.
pub mod error;
mod pg;
/// `DataStore` trait definition.
pub mod store;
/// Domain types shared across the storage layer.
pub mod types;

pub use error::{Error, Result};
pub use pg::PgDataStore;
pub use store::DataStore;
pub use types::*;
