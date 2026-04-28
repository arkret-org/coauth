use figment::Figment;
use serde::de::DeserializeOwned;

type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Trait implemented by all configuration sections to support extraction from
/// a [`Figment`] instance and optional validation.
pub trait ConfigurationSection: Sized + DeserializeOwned {
    /// Path under the root where this section lives.
    /// An empty string means the section is at the root level.
    const PATH: &'static str;

    /// Validate the loaded configuration.
    ///
    /// The default implementation accepts all values.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    fn validate(&self, _figment: &Figment) -> Result<(), BoxedError> {
        Ok(())
    }

    /// Extract and validate from a [`Figment`].
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration could not be loaded
    fn extract(figment: &Figment) -> Result<Self, BoxedError> {
        let section: Self = extract_at_path(figment, Self::PATH)?;
        section.validate(figment)?;
        Ok(section)
    }
}

/// Extension that falls back to [`Default`] when the section key is absent.
pub trait ConfigurationSectionExt: ConfigurationSection + Default {
    /// Extract from the given [`Figment`], or return the default value if
    /// the section key is absent entirely.
    ///
    /// # Errors
    ///
    /// Returns an error if the section is present but invalid.
    fn extract_or_default(figment: &Figment) -> Result<Self, BoxedError> {
        let path = Self::PATH;
        if !path.is_empty() && !figment.contains(path) {
            return Ok(Self::default());
        }

        let section: Self = extract_at_path(figment, path)?;
        section.validate(figment)?;
        Ok(section)
    }
}

impl<T: ConfigurationSection + Default> ConfigurationSectionExt for T {}

/// Helper: extract a `T` from a [`Figment`] using the given dotted path, or
/// from the root when the path is empty.
fn extract_at_path<T: DeserializeOwned>(figment: &Figment, path: &str) -> Result<T, BoxedError> {
    if path.is_empty() {
        Ok(figment.extract()?)
    } else {
        Ok(figment.extract_inner(path)?)
    }
}
