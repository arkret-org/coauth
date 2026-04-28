use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use tracing::Span;

/// Records a SQL statement string into the current tracing span as
/// `db.query.text`. Used by diesel-based repository code.
#[allow(dead_code)]
pub(crate) fn trace_query(sql: &str) {
    Span::current().record(DB_QUERY_TEXT, sql);
}
