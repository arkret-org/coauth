use arkret_identifiers::{IdentifierError, SessionGrantId, encode_digest_token};

pub(crate) fn session_grant_id_from_bytes(value: &[u8]) -> Result<SessionGrantId, IdentifierError> {
    let token: [u8; 33] = value.try_into().map_err(|_| {
        IdentifierError::InvalidId("SessionGrantId storage token must be 33 bytes".to_owned())
    })?;
    SessionGrantId::new(encode_digest_token(SessionGrantId::KIND_PREFIX, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_codec_accepts_only_v1_sha256_session_grant_tokens() {
        let grant_id = SessionGrantId::from_issuance_digest([0x42; 32]);
        assert_eq!(
            session_grant_id_from_bytes(&grant_id.token_bytes()).unwrap(),
            grant_id
        );

        let mut blake3 = grant_id.token_bytes();
        blake3[0] = 0x02;
        assert!(session_grant_id_from_bytes(&blake3).is_err());

        let mut unknown_suite = grant_id.token_bytes();
        unknown_suite[0] = 0x7f;
        assert!(session_grant_id_from_bytes(&unknown_suite).is_err());
        assert!(session_grant_id_from_bytes(&grant_id.token_bytes()[..32]).is_err());

        assert!(SessionGrantId::new(format!("{}=", grant_id.as_str())).is_err());
    }
}
