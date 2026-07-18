//! Shared helpers for PostgreSQL advisory locks.
//!
//! Centralizes the CRC-32 lock-key derivation and the `QueryableByName`
//! result struct that were previously duplicated across crates.

use diesel::sql_types::Bool;

/// Derive a stable `i64` advisory-lock key from a human-readable lock name
/// using CRC-32 (ISO-HDLC).
///
/// Note: the lock name is hashed into a PostgreSQL advisory-lock key. Do not
/// rename a lock name in callers without a coordinated upgrade — it would let
/// an old and a new process hold different locks and step on each other.
#[must_use]
pub fn advisory_lock_key(name: &str) -> i64 {
    const CRC_IEEE: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    i64::from(CRC_IEEE.checksum(name.as_bytes()))
}

/// Result of a `pg_(try_)advisory_lock` query.
#[derive(diesel::QueryableByName)]
pub struct AdvisoryLockResult {
    /// Whether the advisory lock was acquired.
    #[diesel(sql_type = Bool)]
    pub acquired: bool,
}
