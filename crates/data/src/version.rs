/// Holds the compile-time version string of the running application.
#[derive(Debug, Clone, Copy)]
pub struct AppVersion(pub &'static str);
