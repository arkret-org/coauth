//! Canonical-JSON response body for the `/_arkret/gate/*` handlers.
//!
//! These endpoints answer with bytes that were already canonicalized and, in
//! most cases, signed. Re-serializing them through `Json` would recanonicalize
//! a payload whose exact bytes a caller may verify, so the handlers return the
//! byte buffer and this wrapper writes it verbatim under
//! `Content-Type: application/json`.
//!
//! Account handoff, recovery completion, and the three session-grant surfaces
//! each carried a byte-identical copy of this newtype under a different name;
//! one type now serves all of them.

use salvo::prelude::*;

/// A response body of already-canonical JSON bytes, written verbatim.
pub struct ArkretCanonicalJson(pub(crate) Vec<u8>);

impl Scribe for ArkretCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical JSON response body is writable");
    }
}
