use arkret_identifiers::{IdentifierError, SessionGrantId};
use uuid::Uuid;

pub(crate) fn session_grant_id_from_uuid(value: Uuid) -> Result<SessionGrantId, IdentifierError> {
    SessionGrantId::try_from_uuid(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_codec_requires_uuidv7_and_rejects_digest_tokens() {
        let id = SessionGrantId::new_v7_at(1_794_657_600_000);
        assert_eq!(session_grant_id_from_uuid(id.uuid()).unwrap(), id);
        let version_four = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        for invalid in [Uuid::nil(), Uuid::from_u128(1), version_four] {
            assert!(session_grant_id_from_uuid(invalid).is_err());
        }
        assert!(
            SessionGrantId::new("ak:session_grant:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .is_err()
        );
    }
}
