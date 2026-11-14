/// Format a relative time string from a datetime string.
pub fn format_last_active(datetime: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(datetime) {
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(dt);

        if duration.num_minutes() < 3 {
            return crate::translations::t("ui-active-now");
        }
        if duration.num_hours() < 1 {
            let mins = duration.num_minutes();
            return crate::translations::t_count("ui-minutes-ago", mins as u64);
        }
        if duration.num_hours() < 24 {
            let hours = duration.num_hours();
            return crate::translations::t_count("ui-hours-ago", hours as u64);
        }
        if duration.num_days() < 90 {
            let days = duration.num_days();
            return crate::translations::t_count("ui-days-ago", days as u64);
        }
        return crate::translations::t("ui-inactive-90-days");
    }
    datetime.to_owned()
}

/// Format a datetime string to a readable date.
pub fn format_date(datetime: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(datetime) {
        return dt
            .format(&crate::translations::t("ui-date-format"))
            .to_string();
    }
    datetime.to_owned()
}
