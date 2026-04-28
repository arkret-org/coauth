//! Generic `Localized<T>` container for language-tagged values used
//! throughout the Dynamic Client Registration types.

use language_tags::LanguageTag;

/// A collection of localized variants.
///
/// Always includes one non-localized variant. Localized variants are stored
/// as a sorted vector of `(LanguageTag, T)` pairs, kept in lexicographic
/// order by the tag's string representation for deterministic iteration and
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Localized<T> {
    /// The non-localized (default) value, always present for a well-formed
    /// instance.
    default_value: Option<T>,

    /// Language-tagged variants, maintained in sorted order by tag string.
    tagged: Vec<(LanguageTag, T)>,
}

impl<T> Localized<T> {
    /// Constructs a new `Localized` with the given non-localized and localized
    /// variants.
    pub fn new(non_localized: T, localized: impl IntoIterator<Item = (LanguageTag, T)>) -> Self {
        let mut tagged: Vec<(LanguageTag, T)> = localized.into_iter().collect();
        tagged.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
        Self {
            default_value: Some(non_localized),
            tagged,
        }
    }

    /// Returns the number of variants.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.tagged.len() + usize::from(self.default_value.is_some())
    }

    /// Get the non-localized variant.
    pub fn non_localized(&self) -> &T {
        self.default_value
            .as_ref()
            .expect("Localized must have a default value")
    }

    /// Get the non-localized variant.
    pub fn to_non_localized(self) -> T {
        self.default_value
            .expect("Localized must have a default value")
    }

    /// Get the variant corresponding to the given language, if it exists.
    pub fn get(&self, language: Option<&LanguageTag>) -> Option<&T> {
        match language {
            Some(tag) => self
                .tagged
                .iter()
                .find(|(t, _)| t == tag)
                .map(|(_, val)| val),
            None => self.default_value.as_ref(),
        }
    }

    /// Get an iterator over the variants.
    pub fn iter(&self) -> impl Iterator<Item = (Option<&LanguageTag>, &T)> {
        self.default_value
            .iter()
            .map(|val| (None, val))
            .chain(self.tagged.iter().map(|(tag, val)| (Some(tag), val)))
    }

    /// Sort the localized keys. This is inteded to ensure a stable
    /// serialization order when needed.
    pub(super) fn sort(&mut self) {
        self.tagged
            .sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
    }

    /// Access the default value directly.
    pub(crate) fn default_value(&self) -> Option<&T> {
        self.default_value.as_ref()
    }

    /// Access the tagged variants directly.
    pub(crate) fn tagged_pairs(&self) -> &[(LanguageTag, T)] {
        &self.tagged
    }

    /// Construct from separate parts (used during deserialization).
    pub(crate) fn from_parts(default_value: Option<T>, tagged: Vec<(LanguageTag, T)>) -> Self {
        let mut inst = Self {
            default_value,
            tagged,
        };
        inst.sort();
        inst
    }
}

impl<T> From<(T, Vec<(LanguageTag, T)>)> for Localized<T> {
    fn from(t: (T, Vec<(LanguageTag, T)>)) -> Self {
        Localized::from_parts(Some(t.0), t.1)
    }
}
