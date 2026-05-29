// Schema generator binary for policy input types.
//
// Produces JSON schemas that can be used for validating
// policy input types (e.g. for Cedar or a remote HTTP authorization service).

#![expect(
    clippy::disallowed_types,
    reason = "We use Path/PathBuf instead of camino here for simplicity"
)]

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use coauth_policy::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, RegisterInput,
};
use schemars::{JsonSchema, generate::SchemaSettings};

/// Resolve the destination writer: either a file in the output directory
/// or stdout when no directory is provided.
fn destination_writer(output_dir: Option<&Path>, filename: &str) -> Box<dyn std::io::Write> {
    if let Some(dir) = output_dir {
        let target_path = dir.join(filename);
        eprintln!("Writing to {}", target_path.display());
        let handle = std::fs::File::create(target_path).expect("Failed to create file");
        Box::new(std::io::BufWriter::new(handle))
    } else {
        eprintln!("--- {filename} ---");
        Box::new(std::io::stdout())
    }
}

/// Generate a JSON schema for the given type and write it to the destination.
fn generate_and_write_schema<T: JsonSchema>(output_dir: Option<&Path>, filename: &str) {
    let schema_generator = SchemaSettings::draft07().into_generator();
    let root_schema = schema_generator.into_root_schema_for::<T>();

    let mut dest = destination_writer(output_dir, filename);
    serde_json::to_writer_pretty(&mut dest, &root_schema).expect("Failed to serialize schema");
    dest.flush().expect("Failed to flush writer");
}

fn main() {
    let base_dir = std::env::var("OUT_DIR").map(PathBuf::from).ok();
    let base_dir_ref = base_dir.as_deref();

    // Generate schemas for all policy input types
    generate_and_write_schema::<RegisterInput>(base_dir_ref, "register_input.json");
    generate_and_write_schema::<ClientRegistrationInput>(
        base_dir_ref,
        "client_registration_input.json",
    );
    generate_and_write_schema::<AuthorizationGrantInput>(
        base_dir_ref,
        "authorization_grant_input.json",
    );
    generate_and_write_schema::<EmailInput>(base_dir_ref, "email_input.json");
}
