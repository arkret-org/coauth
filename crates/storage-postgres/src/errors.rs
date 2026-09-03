use thiserror::Error;
use ulid::Ulid;

/// Generic error when interacting with the database
#[derive(Debug, Error)]
#[error(transparent)]
pub enum DatabaseError {
    /// An error from the diesel driver
    #[error("Diesel error: {source}")]
    Diesel {
        /// The underlying diesel error
        #[from]
        source: diesel::result::Error,
    },

    /// An error from the async connection pool
    #[error("Connection pool error: {source}")]
    Pool {
        /// The underlying pool error
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// An error which occurred while converting the data from the database
    Inconsistency(#[from] DatabaseInconsistencyError),

    /// An error which happened because the requested database operation is
    /// invalid
    #[error("Invalid database operation")]
    InvalidOperation {
        /// The source of the error, if any
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// An error which happens when an operation affects not enough or too many
    /// rows
    #[error("Expected {expected} rows to be affected, but {actual} rows were affected")]
    RowsAffected {
        /// How many rows were expected to be affected
        expected: u64,

        /// How many rows were actually affected
        actual: u64,
    },

    /// A row could not be written because it would violate a uniqueness
    /// constraint (e.g. a handle/localpart already taken). Distinguished from
    /// the opaque [`Self::Diesel`] case so callers can map a concurrent
    /// insert race to a clean domain conflict instead of a generic 500.
    #[error("Unique constraint violation")]
    UniqueViolation,
}

impl DatabaseError {
    /// Diesel variant: `.execute()` returns `usize` directly.
    pub(crate) fn ensure_affected_rows_usize(
        actual: usize,
        expected: usize,
    ) -> Result<(), DatabaseError> {
        let actual = u64::try_from(actual).unwrap_or(u64::MAX);
        let expected = u64::try_from(expected).unwrap_or(u64::MAX);
        if actual == expected {
            Ok(())
        } else {
            Err(DatabaseError::RowsAffected { expected, actual })
        }
    }

    pub(crate) fn to_invalid_operation<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::InvalidOperation {
            source: Some(Box::new(e)),
        }
    }

    pub(crate) const fn invalid_operation() -> Self {
        Self::InvalidOperation { source: None }
    }

    /// Whether this error represents a uniqueness-constraint violation.
    ///
    /// Returns `true` both for the explicit [`Self::UniqueViolation`] variant
    /// and for a raw diesel `UniqueViolation` database error wrapped in
    /// [`Self::Diesel`], so callers do not have to know which insert strategy
    /// produced the conflict.
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        match self {
            Self::UniqueViolation => true,
            Self::Diesel { source } => matches!(
                source,
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                )
            ),
            _ => false,
        }
    }
}

/// Declare `From<$error> for DatabaseError` mapping onto
/// [`DatabaseError::InvalidOperation`].
///
/// Only failures that a well-formed row and a well-formed caller argument can
/// never provoke belong here: decoding an identifier, a canonical encoding or
/// a JSON payload that this backend itself wrote, and narrowing an integer the
/// schema already constrains. Every such failure means the stored bytes no
/// longer satisfy an invariant the writer enforced, which is exactly what
/// [`DatabaseError::InvalidOperation`] denotes.
///
/// Anything a caller can steer towards a *distinguishable* outcome MUST keep
/// its explicit mapping. In particular a uniqueness conflict has to reach
/// [`DatabaseError::UniqueViolation`] so [`DatabaseError::is_unique_violation`]
/// can turn a concurrent insert into a domain conflict instead of a `500`, and
/// a row-shape mismatch that can name its table and column belongs in
/// [`DatabaseInconsistencyError`] rather than here — a bare `?` would discard
/// the table/column/row breadcrumb those carry.
///
/// The conversion keeps the original error as the `source`, so it is strictly
/// more informative than the `map_err(|_| …)` closures it replaces while
/// producing the same variant: no caller in this workspace discriminates
/// between `InvalidOperation` with and without a source.
macro_rules! invalid_operation_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for DatabaseError {
                fn from(value: $error) -> Self {
                    Self::to_invalid_operation(value)
                }
            }
        )+
    };
}

invalid_operation_from!(
    arkret_canonical::CanonicalError,
    arkret_identifiers::IdentifierError,
    serde_json::Error,
    std::num::TryFromIntError,
);

/// An error which occurred while converting the data from the database
#[derive(Debug, Error)]
pub struct DatabaseInconsistencyError {
    /// The table which was being queried
    table: &'static str,

    /// The column which was being queried
    column: Option<&'static str>,

    /// The row which was being queried
    row: Option<Ulid>,

    /// The source of the error
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl std::fmt::Display for DatabaseInconsistencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Database inconsistency on table {}", self.table)?;
        if let Some(column) = self.column {
            write!(f, " column {column}")?;
        }
        if let Some(row) = self.row {
            write!(f, " row {row}")?;
        }

        Ok(())
    }
}

impl DatabaseInconsistencyError {
    /// Create a new [`DatabaseInconsistencyError`] for the given table
    #[must_use]
    pub(crate) const fn on(table: &'static str) -> Self {
        Self {
            table,
            column: None,
            row: None,
            source: None,
        }
    }

    /// Set the column which was being queried
    #[must_use]
    pub(crate) const fn column(mut self, column: &'static str) -> Self {
        self.column = Some(column);
        self
    }

    /// Set the row which was being queried
    #[must_use]
    pub(crate) const fn row(mut self, row: Ulid) -> Self {
        self.row = Some(row);
        self
    }

    /// Give the source of the error
    #[must_use]
    pub(crate) fn source<E: std::error::Error + Send + Sync + 'static>(
        mut self,
        source: E,
    ) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}
