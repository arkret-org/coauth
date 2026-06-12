// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use coauth_data::personal::session::PersonalSession;
use coauth_data::{BrowserSession, Clock, Session};

use crate::handlers::activity_tracker::ActivityTracker;

/// An activity tracker with an IP address bound to it.
#[derive(Clone)]
pub struct Bound {
    tracker: ActivityTracker,
    ip: Option<IpAddr>,
}

impl Bound {
    /// Create a new bound activity tracker.
    #[must_use]
    pub fn new(tracker: ActivityTracker, ip: Option<IpAddr>) -> Self {
        Self { tracker, ip }
    }

    /// Get the IP address bound to this activity tracker.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// Record activity in an OAuth session.
    pub async fn record_oauth_session(&self, clock: &dyn Clock, session: &Session) {
        self.tracker
            .record_oauth_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a personal session.
    pub async fn record_personal_session(&self, clock: &dyn Clock, session: &PersonalSession) {
        self.tracker
            .record_personal_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a browser session.
    pub async fn record_browser_session(&self, clock: &dyn Clock, session: &BrowserSession) {
        self.tracker
            .record_browser_session(clock, session, self.ip)
            .await;
    }
}
