#![deny(missing_docs, rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]
// derive(JSONSchema) uses &str.to_string()
#![allow(clippy::str_to_string)]

//! Application configuration logic

mod environment;
pub(crate) mod schema;
mod sections;
pub(crate) mod util;

pub use self::environment::{RuntimeEnvironmentPolicy, runtime_var, runtime_var_os};
pub use self::sections::*;
pub use self::util::{ConfigurationSection, ConfigurationSectionExt};
