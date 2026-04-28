use std::sync::LazyLock;

use coauth_data::{BrowserSession, RepositoryAccess};
use salvo::extract::{Extractible, Metadata};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::cookies::{CookieExpiration, CookieJar};

/// An encrypted cookie to save the session ID
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SessionInfo {
    current: Option<Ulid>,
}

impl SessionInfo {
    /// Forge the cookie from a [`BrowserSession`]
    #[must_use]
    pub fn from_session(session: &BrowserSession) -> Self {
        Self {
            current: Some(session.id),
        }
    }

    /// Mark the session as ended
    #[must_use]
    pub fn mark_session_ended(mut self) -> Self {
        self.current = None;
        self
    }

    /// Load the active [`BrowserSession`] from database
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails to load the session.
    pub async fn load_active_session<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<Option<BrowserSession>, E> {
        let Some(session_id) = self.current else {
            return Ok(None);
        };

        let maybe_session = repo
            .browser_session()
            .lookup(session_id)
            .await?
            // Ensure that the session is still active
            .filter(BrowserSession::active);

        Ok(maybe_session)
    }

    /// Get the current session ID, if any
    #[must_use]
    pub fn current_session_id(&self) -> Option<Ulid> {
        self.current
    }
}

pub trait SessionInfoExt {
    #[must_use]
    fn session_info(self) -> (SessionInfo, Self);

    #[must_use]
    fn update_session_info(self, info: &SessionInfo) -> Self;

    #[must_use]
    fn set_session(self, session: &BrowserSession) -> Self
    where
        Self: Sized,
    {
        let session_info = SessionInfo::from_session(session);
        self.update_session_info(&session_info)
    }
}

impl SessionInfoExt for CookieJar {
    fn session_info(self) -> (SessionInfo, Self) {
        let info = match self.load("session") {
            Ok(Some(s)) => s,
            Ok(None) => SessionInfo::default(),
            Err(e) => {
                tracing::error!("failed to load session cookie: {}", e);
                SessionInfo::default()
            }
        };

        let jar = self.update_session_info(&info);
        (info, jar)
    }

    fn update_session_info(self, info: &SessionInfo) -> Self {
        // Long-lived "remember me" session cookie. We use Max-Age (not
        // Expires) so the cookie does not depend on the browser-side wall
        // clock; on the server side, session validity is enforced by the
        // database (`browser_session.finished_at`), not by cookie expiry.
        self.save("session", info, CookieExpiration::permanent_max_age())
    }
}

static SESSION_INFO_METADATA: LazyLock<Metadata> = LazyLock::new(|| Metadata::new("SessionInfo"));

impl<'ex> Extractible<'ex> for SessionInfo {
    fn metadata() -> &'static Metadata {
        &SESSION_INFO_METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(
        req: &'ex mut salvo::Request,
        depot: &'ex mut salvo::Depot,
    ) -> Result<Self, salvo::http::StatusError> {
        let cookie_jar = CookieJar::extract(req, depot).await?;
        let (session_info, _) = cookie_jar.session_info();
        Ok(session_info)
    }
}
