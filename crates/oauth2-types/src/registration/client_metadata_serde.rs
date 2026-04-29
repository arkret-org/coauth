use chrono::Duration;
use coauth_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
    oauth::OAuthClientAuthenticationMethod,
};
use coauth_jose::jwk::PublicJsonWebKeySet;
use language_tags::LanguageTag;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeOwned, MapAccess, Visitor},
    ser::SerializeMap,
};
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use url::Url;

use super::{ClientMetadata, Localized, VerifiedClientMetadata};
use crate::{
    oidc::{ApplicationType, SubjectType},
    requests::GrantType,
    response_type::ResponseType,
};

/// Serialize a `Localized<T>` into map entries: one for the base field name and
/// one for each language-tagged variant as `"field#lang"`.
fn serialize_localized_field<T, M>(
    localized: &Localized<T>,
    map: &mut M,
    field_name: &str,
) -> Result<(), M::Error>
where
    M: SerializeMap,
    T: Serialize,
{
    if let Some(default_val) = localized.default_value() {
        map.serialize_entry(field_name, default_val)?;
    }

    for (tag, value) in localized.tagged_pairs() {
        let tagged_key = format!("{field_name}#{tag}");
        map.serialize_entry(&tagged_key, value)?;
    }

    Ok(())
}

/// Intermediate grouping for localized field deserialization: maps each base
/// field name to its set of language-tagged (and untagged) values.  We use a
/// `Vec` of tuples (rather than a map keyed by `LanguageTag`) because
/// `LanguageTag` does not implement `Ord`.
type GroupedEntries = Vec<(String, Vec<(Option<LanguageTag>, Value)>)>;

/// Find or create a group for the given base field name.
fn get_or_create_group<'a>(
    groups: &'a mut GroupedEntries,
    base: &str,
) -> &'a mut Vec<(Option<LanguageTag>, Value)> {
    let idx = groups.iter().position(|(name, _)| name == base);
    match idx {
        Some(i) => &mut groups[i].1,
        None => {
            groups.push((base.to_owned(), Vec::new()));
            &mut groups.last_mut().expect("just pushed").1
        }
    }
}

/// Parse a grouped field entry into a `Localized<T>`, requiring the
/// untagged (default) variant to be present.
fn parse_localized_field<T>(
    groups: &mut GroupedEntries,
    field_name: &'static str,
) -> Result<Option<Localized<T>>, serde_json::Error>
where
    T: DeserializeOwned,
{
    let idx = groups.iter().position(|(name, _)| name == field_name);
    let Some(idx) = idx else {
        return Ok(None);
    };
    let (_, entries) = groups.remove(idx);

    let mut default_value: Option<T> = None;
    let mut tagged: Vec<(LanguageTag, T)> = Vec::with_capacity(entries.len());

    for (maybe_tag, raw_value) in entries {
        let parsed: T = serde_json::from_value(raw_value)?;
        match maybe_tag {
            None => {
                default_value = Some(parsed);
            }
            Some(tag) => {
                tagged.push((tag, parsed));
            }
        }
    }

    if default_value.is_none() {
        return Err(de::Error::custom(format!(
            "missing non-localized variant of field '{field_name}'"
        )));
    }

    Ok(Some(Localized::from_parts(default_value, tagged)))
}

/// The non-localized fields of `ClientMetadata`, used as a flat serde
/// intermediate representation.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
struct FlatFields {
    redirect_uris: Option<Vec<Url>>,
    response_types: Option<Vec<ResponseType>>,
    grant_types: Option<Vec<GrantType>>,
    token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
    token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
    contacts: Option<Vec<String>>,
    jwks_uri: Option<Url>,
    jwks: Option<PublicJsonWebKeySet>,
    software_id: Option<String>,
    software_version: Option<String>,
    application_type: Option<ApplicationType>,
    sector_identifier_uri: Option<Url>,
    subject_type: Option<SubjectType>,
    id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
    id_token_encrypted_response_alg: Option<JsonWebEncryptionAlg>,
    id_token_encrypted_response_enc: Option<JsonWebEncryptionEnc>,
    userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
    userinfo_encrypted_response_alg: Option<JsonWebEncryptionAlg>,
    userinfo_encrypted_response_enc: Option<JsonWebEncryptionEnc>,
    request_object_signing_alg: Option<JsonWebSignatureAlg>,
    request_object_encryption_alg: Option<JsonWebEncryptionAlg>,
    request_object_encryption_enc: Option<JsonWebEncryptionEnc>,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    default_max_age: Option<Duration>,
    require_auth_time: Option<bool>,
    default_acr_values: Option<Vec<String>>,
    initiate_login_uri: Option<Url>,
    request_uris: Option<Vec<Url>>,
    require_signed_request_object: Option<bool>,
    require_pushed_authorization_requests: Option<bool>,
    introspection_signed_response_alg: Option<JsonWebSignatureAlg>,
    introspection_encrypted_response_alg: Option<JsonWebEncryptionAlg>,
    introspection_encrypted_response_enc: Option<JsonWebEncryptionEnc>,
    post_logout_redirect_uris: Option<Vec<Url>>,
}

/// An opaque wrapper that holds both the flat fields and the localized fields,
/// used to bridge between `ClientMetadata` and serde.
pub struct ClientMetadataSerdeHelper {
    flat: FlatFields,
    client_name: Option<Localized<String>>,
    logo_uri: Option<Localized<Url>>,
    client_uri: Option<Localized<Url>>,
    policy_uri: Option<Localized<Url>>,
    tos_uri: Option<Localized<Url>>,
}

impl From<VerifiedClientMetadata> for ClientMetadataSerdeHelper {
    fn from(verified: VerifiedClientMetadata) -> Self {
        verified.inner.into()
    }
}

impl From<ClientMetadata> for ClientMetadataSerdeHelper {
    fn from(md: ClientMetadata) -> Self {
        ClientMetadataSerdeHelper {
            flat: FlatFields {
                redirect_uris: md.redirect_uris,
                response_types: md.response_types,
                grant_types: md.grant_types,
                token_endpoint_auth_method: md.token_endpoint_auth_method,
                token_endpoint_auth_signing_alg: md.token_endpoint_auth_signing_alg,
                contacts: md.contacts,
                jwks_uri: md.jwks_uri,
                jwks: md.jwks,
                software_id: md.software_id,
                software_version: md.software_version,
                application_type: md.application_type,
                sector_identifier_uri: md.sector_identifier_uri,
                subject_type: md.subject_type,
                id_token_signed_response_alg: md.id_token_signed_response_alg,
                id_token_encrypted_response_alg: md.id_token_encrypted_response_alg,
                id_token_encrypted_response_enc: md.id_token_encrypted_response_enc,
                userinfo_signed_response_alg: md.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: md.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: md.userinfo_encrypted_response_enc,
                request_object_signing_alg: md.request_object_signing_alg,
                request_object_encryption_alg: md.request_object_encryption_alg,
                request_object_encryption_enc: md.request_object_encryption_enc,
                default_max_age: md.default_max_age,
                require_auth_time: md.require_auth_time,
                default_acr_values: md.default_acr_values,
                initiate_login_uri: md.initiate_login_uri,
                request_uris: md.request_uris,
                require_signed_request_object: md.require_signed_request_object,
                require_pushed_authorization_requests: md.require_pushed_authorization_requests,
                introspection_signed_response_alg: md.introspection_signed_response_alg,
                introspection_encrypted_response_alg: md.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: md.introspection_encrypted_response_enc,
                post_logout_redirect_uris: md.post_logout_redirect_uris,
            },
            client_name: md.client_name,
            logo_uri: md.logo_uri,
            client_uri: md.client_uri,
            policy_uri: md.policy_uri,
            tos_uri: md.tos_uri,
        }
    }
}

impl From<ClientMetadataSerdeHelper> for ClientMetadata {
    fn from(helper: ClientMetadataSerdeHelper) -> Self {
        let f = helper.flat;
        ClientMetadata {
            redirect_uris: f.redirect_uris,
            response_types: f.response_types,
            grant_types: f.grant_types,
            token_endpoint_auth_method: f.token_endpoint_auth_method,
            token_endpoint_auth_signing_alg: f.token_endpoint_auth_signing_alg,
            client_name: helper.client_name,
            logo_uri: helper.logo_uri,
            client_uri: helper.client_uri,
            policy_uri: helper.policy_uri,
            tos_uri: helper.tos_uri,
            contacts: f.contacts,
            jwks_uri: f.jwks_uri,
            jwks: f.jwks,
            software_id: f.software_id,
            software_version: f.software_version,
            application_type: f.application_type,
            sector_identifier_uri: f.sector_identifier_uri,
            subject_type: f.subject_type,
            id_token_signed_response_alg: f.id_token_signed_response_alg,
            id_token_encrypted_response_alg: f.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc: f.id_token_encrypted_response_enc,
            userinfo_signed_response_alg: f.userinfo_signed_response_alg,
            userinfo_encrypted_response_alg: f.userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc: f.userinfo_encrypted_response_enc,
            request_object_signing_alg: f.request_object_signing_alg,
            request_object_encryption_alg: f.request_object_encryption_alg,
            request_object_encryption_enc: f.request_object_encryption_enc,
            default_max_age: f.default_max_age,
            require_auth_time: f.require_auth_time,
            default_acr_values: f.default_acr_values,
            initiate_login_uri: f.initiate_login_uri,
            request_uris: f.request_uris,
            require_signed_request_object: f.require_signed_request_object,
            require_pushed_authorization_requests: f.require_pushed_authorization_requests,
            introspection_signed_response_alg: f.introspection_signed_response_alg,
            introspection_encrypted_response_alg: f.introspection_encrypted_response_alg,
            introspection_encrypted_response_enc: f.introspection_encrypted_response_enc,
            post_logout_redirect_uris: f.post_logout_redirect_uris,
        }
    }
}

impl Serialize for ClientMetadataSerdeHelper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize the flat fields to a serde_json::Value first, then merge
        // the localized fields in the correct position among the map entries.
        let flat_value = serde_json::to_value(&self.flat).map_err(serde::ser::Error::custom)?;
        let flat_obj = flat_value
            .as_object()
            .expect("FlatFields serializes to an object");

        // Count entries for the map: flat entries + localized entries.
        // We sum the lengths individually because the localized fields have
        // different generic type parameters.
        let localized_entry_count = self.client_name.as_ref().map_or(0, Localized::len)
            + self.logo_uri.as_ref().map_or(0, Localized::len)
            + self.client_uri.as_ref().map_or(0, Localized::len)
            + self.policy_uri.as_ref().map_or(0, Localized::len)
            + self.tos_uri.as_ref().map_or(0, Localized::len);

        let mut map = serializer.serialize_map(Some(flat_obj.len() + localized_entry_count))?;

        // We want to serialize flat fields in order, injecting localized fields
        // at the right spot. We serialize flat fields first up to "contacts",
        // then localized fields, then the rest.
        let localized_anchor = "contacts";
        let mut localized_emitted = false;

        for (key, value) in flat_obj {
            map.serialize_entry(key, value)?;

            if key == localized_anchor && !localized_emitted {
                self.emit_localized_fields(&mut map)?;
                localized_emitted = true;
            }
        }

        // If the anchor key was absent (e.g. contacts was None and thus
        // skipped), emit localized fields at the end.
        if !localized_emitted {
            self.emit_localized_fields(&mut map)?;
        }

        map.end()
    }
}

impl ClientMetadataSerdeHelper {
    fn emit_localized_fields<M>(&self, map: &mut M) -> Result<(), M::Error>
    where
        M: SerializeMap,
    {
        if let Some(name) = &self.client_name {
            serialize_localized_field(name, map, "client_name")?;
        }
        if let Some(uri) = &self.logo_uri {
            serialize_localized_field(uri, map, "logo_uri")?;
        }
        if let Some(uri) = &self.client_uri {
            serialize_localized_field(uri, map, "client_uri")?;
        }
        if let Some(uri) = &self.policy_uri {
            serialize_localized_field(uri, map, "policy_uri")?;
        }
        if let Some(uri) = &self.tos_uri {
            serialize_localized_field(uri, map, "tos_uri")?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ClientMetadataSerdeHelper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ClientMetadataHelperVisitor)
    }
}

/// The set of field names that carry localized variants.
const LOCALIZED_FIELD_NAMES: &[&str] = &[
    "client_name",
    "logo_uri",
    "client_uri",
    "policy_uri",
    "tos_uri",
];

/// Returns `true` if a key belongs to a localized field (either the base name
/// or a language-tagged variant like `"client_name#fr"`).
fn is_localized_key(key: &str) -> bool {
    let base = key.split_once('#').map_or(key, |(base, _)| base);
    LOCALIZED_FIELD_NAMES.contains(&base)
}

struct ClientMetadataHelperVisitor;

impl<'de> Visitor<'de> for ClientMetadataHelperVisitor {
    type Value = ClientMetadataSerdeHelper;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a map representing client metadata")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        // We collect all entries into a single JSON object, then split them
        // into "flat" (non-localized) entries and "grouped" (localized)
        // entries.
        let mut flat_entries = serde_json::Map::new();
        let mut grouped: GroupedEntries = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            let value: Value = map.next_value()?;

            if is_localized_key(&key) {
                let (base, maybe_tag) = if let Some((base, lang_str)) = key.split_once('#') {
                    let tag = LanguageTag::parse(lang_str).map_err(|_| {
                        de::Error::invalid_value(de::Unexpected::Str(lang_str), &"language tag")
                    })?;
                    (base.to_owned(), Some(tag))
                } else {
                    (key, None)
                };

                let group = get_or_create_group(&mut grouped, &base);
                group.push((maybe_tag, value));
            } else {
                flat_entries.insert(key, value);
            }
        }

        // Deserialize the flat fields from the collected JSON object.
        let flat_value = Value::Object(flat_entries);
        let flat: FlatFields = serde_json::from_value(flat_value).map_err(de::Error::custom)?;

        // Parse each localized field group.
        let client_name =
            parse_localized_field(&mut grouped, "client_name").map_err(de::Error::custom)?;
        let logo_uri =
            parse_localized_field(&mut grouped, "logo_uri").map_err(de::Error::custom)?;
        let client_uri =
            parse_localized_field(&mut grouped, "client_uri").map_err(de::Error::custom)?;
        let policy_uri =
            parse_localized_field(&mut grouped, "policy_uri").map_err(de::Error::custom)?;
        let tos_uri = parse_localized_field(&mut grouped, "tos_uri").map_err(de::Error::custom)?;

        Ok(ClientMetadataSerdeHelper {
            flat,
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot;

    use super::*;

    #[test]
    fn deserialize_localized_fields() {
        let metadata = serde_json::json!({
            "redirect_uris": ["http://localhost/oidc"],
            "client_name": "Postbox",
            "client_name#fr": "Boîte à lettres",
            "client_uri": "https://localhost/",
            "client_uri#fr": "https://localhost/fr",
            "client_uri#de": "https://localhost/de",
        });

        let metadata: ClientMetadata = serde_json::from_value(metadata).unwrap();

        let name = metadata.client_name.unwrap();
        assert_eq!(name.non_localized(), "Postbox");
        assert_eq!(
            name.get(Some(&LanguageTag::parse("fr").unwrap())).unwrap(),
            "Boîte à lettres"
        );
        assert_eq!(name.get(Some(&LanguageTag::parse("de").unwrap())), None);

        let client_uri = metadata.client_uri.unwrap();
        assert_eq!(client_uri.non_localized().as_ref(), "https://localhost/");
        assert_eq!(
            client_uri
                .get(Some(&LanguageTag::parse("fr").unwrap()))
                .unwrap()
                .as_ref(),
            "https://localhost/fr"
        );
        assert_eq!(
            client_uri
                .get(Some(&LanguageTag::parse("de").unwrap()))
                .unwrap()
                .as_ref(),
            "https://localhost/de"
        );
    }

    #[test]
    fn serialize_localized_fields() {
        let client_name = Localized::new(
            "Postbox".to_owned(),
            [(
                LanguageTag::parse("fr").unwrap(),
                "Boîte à lettres".to_owned(),
            )],
        );
        let client_uri = Localized::new(
            Url::parse("https://localhost").unwrap(),
            [
                (
                    LanguageTag::parse("fr").unwrap(),
                    Url::parse("https://localhost/fr").unwrap(),
                ),
                (
                    LanguageTag::parse("de").unwrap(),
                    Url::parse("https://localhost/de").unwrap(),
                ),
            ],
        );
        let metadata = ClientMetadata {
            redirect_uris: Some(vec![Url::parse("http://localhost/oidc").unwrap()]),
            client_name: Some(client_name),
            client_uri: Some(client_uri),
            ..Default::default()
        }
        .validate()
        .unwrap();

        assert_yaml_snapshot!(metadata, @r###"
        redirect_uris:
          - "http://localhost/oidc"
        client_name: Postbox
        "client_name#fr": Boîte à lettres
        client_uri: "https://localhost/"
        "client_uri#de": "https://localhost/de"
        "client_uri#fr": "https://localhost/fr"
        "###);

        // Do a roundtrip, we should get the same metadata back with the same order
        let metadata: ClientMetadata =
            serde_json::from_value(serde_json::to_value(metadata).unwrap()).unwrap();
        let metadata = metadata.validate().unwrap();
        assert_yaml_snapshot!(metadata, @r###"
        redirect_uris:
          - "http://localhost/oidc"
        client_name: Postbox
        "client_name#fr": Boîte à lettres
        client_uri: "https://localhost/"
        "client_uri#de": "https://localhost/de"
        "client_uri#fr": "https://localhost/fr"
        "###);
    }
}
