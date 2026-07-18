//! Storage-neutral domain models shared by the coauth application, storage
//! ports, PostgreSQL adapters and private admin API mappings.

pub mod capability;
pub mod organization;

pub use capability::*;
pub use organization::*;
