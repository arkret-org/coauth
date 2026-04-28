use std::hash::Hash;

use serde::{
    Deserialize, Serialize, Serializer,
    ser::{SerializeMap, SerializeStruct},
};

/// Marker trait for form field enum types, controlling which values to retain
/// (e.g. password fields should not be retained).
pub trait FormField: Copy + Hash + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> {
    /// Return false for fields where values should not be kept (e.g. password
    /// fields)
    fn keep(&self) -> bool;

    /// Retain or clear the serialized field value according to the field
    /// policy.
    fn retain_value(&self, value: Option<String>) -> Option<String> {
        self.keep().then_some(value).flatten()
    }
}

/// Describes a single field-level validation error
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FieldError {
    /// A required field is missing
    Required,
    /// An unspecified error on the field
    Unspecified,
    /// Invalid value for this field
    Invalid,
    /// The password confirmation doesn't match the password
    PasswordMismatch,
    /// That value already exists
    Exists,
    /// Denied by the policy
    Policy {
        /// Well-known policy code
        code: Option<&'static str>,
        /// Message for this policy violation
        message: String,
    },
}

/// Describes a form-level validation error
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FormError {
    /// The given credentials are not valid
    InvalidCredentials,
    /// Password fields don't match
    PasswordMismatch,
    /// There was an internal error
    Internal,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Denied by the policy
    Policy {
        /// Well-known policy code
        code: Option<&'static str>,
        /// Message for this policy violation
        message: String,
    },
    /// Failed to validate CAPTCHA
    Captcha,
}

/// Tracks the current value and validation errors for a single form field.
#[derive(Debug, Default, Serialize)]
struct FieldSnapshot {
    value: Option<String>,
    errors: Vec<FieldError>,
}

/// An ordered collection of named fields, preserving insertion order.
///
/// Uses a `Vec` of key-value pairs so that serialization order is
/// deterministic and matches the form layout.
#[derive(Debug)]
struct FieldStore<K> {
    entries: Vec<(K, FieldSnapshot)>,
}

impl<K> Default for FieldStore<K> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<K: Copy + Eq> FieldStore<K> {
    fn lookup(&self, key: K) -> Option<&FieldSnapshot> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, snap)| snap)
    }

    fn entry_mut(&mut self, key: K) -> &mut FieldSnapshot {
        if let Some(pos) = self.entries.iter().position(|(k, _)| *k == key) {
            return &mut self.entries[pos].1;
        }
        self.entries.push((key, FieldSnapshot::default()));
        &mut self
            .entries
            .last_mut()
            .expect("entries must be non-empty after push")
            .1
    }

    fn insert(&mut self, key: K, value: Option<String>) {
        self.entries.push((
            key,
            FieldSnapshot {
                value,
                errors: Vec::new(),
            },
        ));
    }
}

impl<K: FormField> FieldStore<K> {
    fn populate_from<F: Serialize>(form: &F) -> Self {
        let json_val = serde_json::to_value(form).expect("form serialization should not fail");
        let raw_map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(json_val).expect("form serialization should produce an object");

        let mut store = Self::default();
        for (raw_name, raw_value) in raw_map {
            let Some(field_key) = try_decode_key::<K>(raw_name) else {
                continue;
            };
            let retained = field_key.retain_value(extract_string_value(raw_value));
            store.insert(field_key, retained);
        }
        store
    }
}

impl<K: Serialize> Serialize for FieldStore<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (key, snapshot) in &self.entries {
            map.serialize_entry(key, snapshot)?;
        }
        map.end()
    }
}

// -- Validation state -------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Validity {
    #[default]
    Clean,
    HasErrors,
}

// -- FormState --------------------------------------------------------------

/// Tracks state and validation errors for a form and its individual fields.
///
/// The type parameter `K` represents the field name enum.
#[derive(Debug)]
pub struct FormState<K: Hash + Eq> {
    fields: FieldStore<K>,
    errors: Vec<FormError>,
    validity: Validity,
}

impl<K: Hash + Eq> Default for FormState<K> {
    fn default() -> Self {
        Self {
            fields: FieldStore::default(),
            errors: Vec::new(),
            validity: Validity::Clean,
        }
    }
}

impl<K> Serialize for FormState<K>
where
    K: Hash + Eq + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FormState", 2)?;
        state.serialize_field("fields", &self.fields)?;
        state.serialize_field("errors", &self.errors)?;
        state.end()
    }
}

impl<K: FormField> FormState<K> {
    /// Build a [`FormState`] from a serializable form struct.
    ///
    /// Field values are retained or cleared based on the [`FormField::keep`]
    /// implementation for each key.
    ///
    /// # Panics
    ///
    /// If the form fails to serialize, or the form field keys fail to
    /// deserialize
    pub fn from_form<F: Serialize>(form: &F) -> Self {
        Self {
            fields: FieldStore::populate_from(form),
            errors: Vec::new(),
            validity: Validity::Clean,
        }
    }

    /// Add an error on a form field
    pub fn add_error_on_field(&mut self, field: K, error: FieldError) {
        self.fields.entry_mut(field).errors.push(error);
        self.validity = Validity::HasErrors;
    }

    /// Add an error on a form field
    #[must_use]
    pub fn with_error_on_field(mut self, field: K, error: FieldError) -> Self {
        self.add_error_on_field(field, error);
        self
    }

    /// Add an error on the form
    pub fn add_error_on_form(&mut self, error: FormError) {
        self.errors.push(error);
        self.validity = Validity::HasErrors;
    }

    /// Add an error on the form
    #[must_use]
    pub fn with_error_on_form(mut self, error: FormError) -> Self {
        self.add_error_on_form(error);
        self
    }

    /// Set a value on the form
    pub fn set_value(&mut self, field: K, value: Option<String>) {
        self.fields.entry_mut(field).value = value;
    }

    /// Checks if a field contains a value
    pub fn has_value(&self, field: K) -> bool {
        self.fields
            .lookup(field)
            .is_some_and(|snap| snap.value.is_some())
    }

    /// Returns `true` if the form has no error attached to it
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validity == Validity::Clean
    }
}

// -- Key decoding helpers ---------------------------------------------------

/// Intermediate enum used during deserialization to handle both known and
/// unknown field keys gracefully.
#[derive(Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
enum MaybeKnownKey<K> {
    Known(K),
    Unknown(String),
}

fn try_decode_key<K>(raw: String) -> Option<K>
where
    K: for<'de> Deserialize<'de>,
{
    let decoded: MaybeKnownKey<K> = serde_json::from_value(serde_json::Value::String(raw))
        .expect("field key deserialization should not fail");
    match decoded {
        MaybeKnownKey::Known(k) => Some(k),
        MaybeKnownKey::Unknown(_) => None,
    }
}

fn extract_string_value(value: serde_json::Value) -> Option<String> {
    serde_json::from_value(value).expect("field value deserialization should not fail")
}

// -- ToFormState convenience trait ------------------------------------------

/// Utility trait to help creating [`FormState`] out of a form
pub trait ToFormState: Serialize {
    /// The enum used for field names
    type Field: FormField;

    /// Generate a [`FormState`] out of [`Self`]
    ///
    /// # Panics
    ///
    /// If the form fails to serialize or [`Self::Field`] fails to deserialize
    fn to_form_state(&self) -> FormState<Self::Field> {
        FormState::from_form(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct SampleForm {
        foo: String,
        bar: String,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum SampleField {
        Foo,
        Bar,
    }

    impl FormField for SampleField {
        fn keep(&self) -> bool {
            matches!(self, Self::Foo)
        }
    }

    impl ToFormState for SampleForm {
        type Field = SampleField;
    }

    #[test]
    fn form_state_serialization() {
        let form = SampleForm {
            foo: "john".to_owned(),
            bar: "hunter2".to_owned(),
        };

        let state = form.to_form_state();
        let state = serde_json::to_value(state).unwrap();
        assert_eq!(
            state,
            serde_json::json!({
                "errors": [],
                "fields": {
                    "foo": {
                        "errors": [],
                        "value": "john",
                    },
                    "bar": {
                        "errors": [],
                        "value": null
                    },
                }
            })
        );

        let form = SampleForm {
            foo: String::new(),
            bar: String::new(),
        };
        let state = form
            .to_form_state()
            .with_error_on_field(SampleField::Foo, FieldError::Required)
            .with_error_on_field(SampleField::Bar, FieldError::Required)
            .with_error_on_form(FormError::InvalidCredentials);

        let state = serde_json::to_value(state).unwrap();
        assert_eq!(
            state,
            serde_json::json!({
                "errors": [{"kind": "invalid_credentials"}],
                "fields": {
                    "foo": {
                        "errors": [{"kind": "required"}],
                        "value": "",
                    },
                    "bar": {
                        "errors": [{"kind": "required"}],
                        "value": null
                    },
                }
            })
        );
    }
}
