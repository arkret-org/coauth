/// Get ISO date string for 90 days ago (for inactive session filter).
pub fn get_ninety_days_ago() -> String {
    let now = chrono::Utc::now();
    let ninety_days_ago = now - chrono::Duration::days(90);
    ninety_days_ago.format("%Y-%m-%dT00:00:00Z").to_string()
}

/// Extract device ID from an OAuth2 scope string.
/// Looks for "urn:matrix:org.matrix.msc2967.client:device:" prefix.
pub fn device_id_from_scope(scope: &str) -> Option<String> {
    for part in scope.split_whitespace() {
        if let Some(device_id) = part.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:") {
            if !device_id.is_empty() {
                return Some(device_id.to_string());
            }
        }
    }
    None
}

/// Simplify a URL by removing protocol, trailing slash, search and hash.
pub fn simplify_url(url: &str) -> String {
    let simplified = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if let Some(pos) = simplified.find('?') {
        return simplified[..pos].to_string();
    }
    if let Some(pos) = simplified.find('#') {
        return simplified[..pos].to_string();
    }
    simplified.to_string()
}

/// Format a relative time string from a datetime string.
pub fn format_last_active(datetime: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(datetime) {
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(dt);

        if duration.num_minutes() < 3 {
            return "Active now".to_string();
        }
        if duration.num_hours() < 1 {
            let mins = duration.num_minutes();
            return format!("{mins} minutes ago");
        }
        if duration.num_hours() < 24 {
            let hours = duration.num_hours();
            return format!("{hours} hours ago");
        }
        if duration.num_days() < 90 {
            let days = duration.num_days();
            return format!("{days} days ago");
        }
        return "Inactive for 90+ days".to_string();
    }
    datetime.to_string()
}

/// Format a datetime string to a readable date.
pub fn format_date(datetime: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(datetime) {
        return dt.format("%b %d, %Y %H:%M").to_string();
    }
    datetime.to_string()
}
