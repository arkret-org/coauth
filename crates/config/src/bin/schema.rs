use schemars::generate::SchemaSettings;

fn main() {
    let generator = SchemaSettings::draft07().into_generator();
    let schema = generator.into_root_schema_for::<coauth_config::RootConfig>();

    serde_json::to_writer_pretty(std::io::stdout(), &schema).expect("Failed to serialize schema");
}
