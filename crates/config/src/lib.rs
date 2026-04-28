#![deny(missing_docs, rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]
// derive(JSONSchema) uses &str.to_string()
#![allow(clippy::str_to_string)]

//! Application configuration logic

#[cfg(all(feature = "docker", feature = "dist"))]
compile_error!("Only one of the `docker` and `dist` features can be enabled at once");

pub(crate) mod schema;
mod sections;
pub(crate) mod util;

pub use self::{
    sections::*,
    util::{ConfigurationSection, ConfigurationSectionExt},
};
