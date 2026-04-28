/// Defines an IANA registry enum with an `Unknown(String)` catch-all variant.
///
/// Automatically derives `Display`, `FromStr` (infallible), `Serialize`,
/// `Deserialize`, and `schemars::JsonSchema`.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[doc = $doc:expr])*
                $variant:ident => $str:expr
            ),+
            $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $(
                $(#[doc = $doc])*
                $variant,
            )+
            /// An unknown value.
            Unknown(String),
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $(Self::$variant => f.write_str($str),)+
                    Self::Unknown(v) => f.write_str(v),
                }
            }
        }

        impl core::str::FromStr for $name {
            type Err = core::convert::Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $($str => Self::$variant,)+
                    other => Self::Unknown(other.to_owned()),
                })
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                Ok(s.parse().unwrap()) // Infallible
            }
        }

        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
                let known = vec![
                    $(schemars::json_schema!({ "const": $str }),)+
                ];
                schemars::json_schema!({
                    "description": concat!("IANA registry: ", stringify!($name)),
                    "anyOf": known,
                })
            }
        }
    };
}

/// Defines an IANA registry enum **without** a catch-all variant.
///
/// `FromStr` returns `ParseError` for unrecognised values.
macro_rules! closed_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[doc = $doc:expr])*
                $variant:ident => $str:expr
            ),+
            $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $(
                $(#[doc = $doc])*
                $variant,
            )+
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $(Self::$variant => f.write_str($str),)+
                }
            }
        }

        impl core::str::FromStr for $name {
            type Err = crate::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($str => Ok(Self::$variant),)+
                    _ => Err(crate::ParseError::new()),
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
                let known = vec![
                    $(schemars::json_schema!({ "const": $str }),)+
                ];
                schemars::json_schema!({
                    "description": concat!("IANA registry: ", stringify!($name)),
                    "anyOf": known,
                })
            }
        }
    };
}

pub(crate) use closed_enum;
pub(crate) use open_enum;
