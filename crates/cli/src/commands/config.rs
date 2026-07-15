use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use coauth_backend::RequestBuilderExt as _;
use coauth_backend::util::{database_url_from_config, diesel_pool_from_config};
use coauth_config::{
    ConfigurationSection, IdentityRegistryConfig, IdentityRegistryKind, PrincipalServerConfig,
    RootConfig, SyncConfig,
};
use coauth_data::{Clock, SystemClock};
use ed25519_dalek::{Signer, SigningKey};
use figment::Figment;
use rand::rngs::OsRng;
use rand_core::SeedableRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{info, info_span};
use url::Url;

const DEV_DATABASE_URI: &str = "postgresql://coauth:coauth@localhost/coauth";
const DEV_PUBLIC_BASE: &str = "https://auth.local.host/";
const DEV_SERVICE_ID: &str =
    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:auth.local.host:webvh:service";
const DEV_SOLAND_URL: &str = "https://local.host/";
const DEV_SOLAND_IDENTITY_RESOLVER_URL: &str = "https://local.host/_arkret/root/identity/resolve";
const DEV_SOLAND_SERVICE_ID: &str =
    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:service";
const DEV_SOLAND_SESSION_GRANT_BEARER: &str = "local-coauth-session-grant-introspection";
const DEV_SOLAND_WEBVH_REGISTRATION_BEARER: &str = "local-soland-webvh-registration";

const DEFAULT_SERVICE_ID_PATH: &str = "webvh/service";
const SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";
const SERVICE_ID_MISSING_HELP: &str = concat!(
    "coauth config generate requires arkret.service_id for organization deployments. ",
    "For local development run `coauth config generate --dev -o config.dev.yaml`. ",
    "For production run `coauth config service-id init --starid-url <https://starid.example> ",
    "--host <auth.example.com> --key-output <service-id-keys.yaml>` and copy the emitted ",
    "`arkret.service_id` into your config."
);

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Dump the current configuration as YAML
    Dump {
        /// Destination file path; defaults to stdout when omitted
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,
    },

    /// Validate the configuration file
    Check,

    /// Produce a fresh configuration file with generated secrets
    Generate(GenerateOptions),

    /// Create and manage coauth service DID material
    ServiceId(ServiceIdOptions),

    /// Synchronise clients and providers from the config into the database
    Sync {
        /// Remove database entries that are no longer present in the config
        #[clap(long)]
        prune: bool,

        /// Preview changes without writing to the database
        #[clap(long)]
        dry_run: bool,
    },
}

#[derive(Args, Debug)]
struct GenerateOptions {
    /// Destination file path; defaults to stdout when omitted
    #[clap(short, long)]
    output: Option<Utf8PathBuf>,

    /// Generate a local development config that can pass fail-closed validation
    #[clap(long)]
    dev: bool,

    /// Service DID to write into arkret.service_id for production configs
    #[clap(long)]
    service_id: Option<String>,

    /// Override http.public_base and http.issuer in the generated config
    #[clap(long)]
    public_base: Option<Url>,

    /// Override database.uri in the generated config
    #[clap(long)]
    database_uri: Option<String>,
}

#[derive(Args, Debug)]
struct ServiceIdOptions {
    #[command(subcommand)]
    command: ServiceIdCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceIdCommand {
    /// Mint a did:webvh service DID through starid and print the config snippet
    Init(ServiceIdInitOptions),
}

#[derive(Args, Debug)]
struct ServiceIdInitOptions {
    /// Base URL of the starid deployment, for example https://starid.example
    #[clap(long)]
    starid_url: Url,

    /// Public host that will serve the coauth service DID, for example auth.example.com
    #[clap(long)]
    host: String,

    /// Optional public port embedded in the did:webvh identifier
    #[clap(long)]
    port: Option<u16>,

    /// DID path beneath the host; defaults to /webvh/service
    #[clap(long, default_value = DEFAULT_SERVICE_ID_PATH)]
    path: String,

    /// File that receives the generated private DID/update key seeds
    #[clap(long)]
    key_output: Utf8PathBuf,

    /// starid admin bearer token; when omitted, admin-token-env is consulted
    #[clap(long)]
    admin_token: Option<String>,

    /// Environment variable that may contain the starid admin bearer token
    #[clap(long, default_value = "STARID_ADMIN_TOKEN")]
    admin_token_env: String,

    /// Output format for the public config result
    #[clap(long, value_enum, default_value_t = ServiceIdOutput::Yaml)]
    output: ServiceIdOutput,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ServiceIdOutput {
    /// Print a YAML snippet ready to merge into config.yaml
    Yaml,
    /// Print only the minted DID
    Did,
    /// Print machine-readable public metadata
    Json,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Dump { output } => Self::handle_dump(figment, output).await,
            Command::Check => Self::handle_check(figment),
            Command::Generate(options) => Self::handle_generate(options).await,
            Command::ServiceId(options) => Self::handle_service_id(options).await,
            Command::Sync { prune, dry_run } => Self::handle_sync(figment, prune, dry_run).await,
        }
    }

    async fn handle_dump(figment: &Figment, dest: Option<Utf8PathBuf>) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.dump").entered();

        let root = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let yaml = serde_yaml_ng::to_string(&root)?;

        write_output(&yaml, dest.as_deref()).await?;
        Ok(ExitCode::SUCCESS)
    }

    fn handle_check(figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.check").entered();

        let _validated = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        info!("Configuration file looks good");

        Ok(ExitCode::SUCCESS)
    }

    async fn handle_generate(options: GenerateOptions) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.generate").entered();

        if !options.dev && options.service_id.is_none() {
            bail!(SERVICE_ID_MISSING_HELP);
        }

        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let mut generated = RootConfig::generate(&mut rng).await?;
        apply_generated_config_options(&mut generated, &options)?;
        let yaml = serde_yaml_ng::to_string(&generated)?;

        write_output(&yaml, options.output.as_deref()).await?;
        Ok(ExitCode::SUCCESS)
    }

    async fn handle_service_id(options: ServiceIdOptions) -> anyhow::Result<ExitCode> {
        match options.command {
            ServiceIdCommand::Init(options) => handle_service_id_init(options).await,
        }
    }

    async fn handle_sync(
        figment: &Figment,
        prune: bool,
        dry_run: bool,
    ) -> anyhow::Result<ExitCode> {
        let cfg = SyncConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let clock = SystemClock::default();
        let encrypter = cfg.secrets.encrypter().await?;

        let db_url = database_url_from_config(&cfg.database)?;
        let pool = diesel_pool_from_config(&cfg.database).await?;

        coauth_data::migrate(&pool, &db_url)
            .await
            .context("could not run migrations")?;

        let conn = pool
            .get()
            .await
            .context("could not get connection from pool")?;

        coauth_backend::sync::config_sync(
            cfg.upstream_oauth,
            cfg.clients,
            conn,
            &encrypter,
            &clock,
            prune,
            dry_run,
        )
        .await
        .context("could not sync the configuration with the database")?;

        Ok(ExitCode::SUCCESS)
    }
}

fn apply_generated_config_options(
    config: &mut RootConfig,
    options: &GenerateOptions,
) -> anyhow::Result<()> {
    if options.dev {
        config.database.uri = Some(
            options
                .database_uri
                .clone()
                .unwrap_or_else(|| DEV_DATABASE_URI.to_owned()),
        );
        let public_base = options
            .public_base
            .clone()
            .unwrap_or_else(|| DEV_PUBLIC_BASE.parse().expect("valid dev public base"));
        config.http.public_base = public_base.clone();
        config.http.issuer = Some(public_base);
        config.arkret.service_id = Some(
            options
                .service_id
                .clone()
                .unwrap_or_else(|| DEV_SERVICE_ID.to_owned()),
        );
        config.arkret.principal_server_url =
            Some(DEV_SOLAND_URL.parse().expect("valid dev soland URL"));
        config.arkret.principal_servers = vec![PrincipalServerConfig {
            name: "soland-dev".to_owned(),
            audience: Some(DEV_SOLAND_SERVICE_ID.to_owned()),
            endpoint: DEV_SOLAND_URL.parse().expect("valid dev soland URL"),
            did: Some(DEV_SOLAND_SERVICE_ID.to_owned()),
            session_grant_introspection_bearer: Some(DEV_SOLAND_SESSION_GRANT_BEARER.to_owned()),
            embedded_webvh_registration_bearer: Some(
                DEV_SOLAND_WEBVH_REGISTRATION_BEARER.to_owned(),
            ),
        }];
        config.arkret.identity_registry = Some(IdentityRegistryConfig {
            kind: IdentityRegistryKind::PublicDidResolver,
            resolver: DEV_SOLAND_IDENTITY_RESOLVER_URL
                .parse()
                .expect("valid dev identity resolver URL"),
            proof_required_for_pairwise: false,
        });
    } else {
        config.arkret.service_id.clone_from(&options.service_id);
        if let Some(public_base) = options.public_base.clone() {
            config.http.public_base = public_base.clone();
            config.http.issuer = Some(public_base);
        }
        if let Some(database_uri) = options.database_uri.clone() {
            config.database.uri = Some(database_uri);
        }
    }

    Ok(())
}

async fn handle_service_id_init(options: ServiceIdInitOptions) -> anyhow::Result<ExitCode> {
    let _span = info_span!("cli.config.service_id.init").entered();

    let host = options.host.trim();
    if host.is_empty() {
        bail!("--host must not be empty");
    }
    let path = normalize_service_id_path(&options.path)?;
    let path_segments = webvh_path_segments(&path)?;

    let mut rng = OsRng;
    let did_signing = SigningKey::generate(&mut rng);
    let update_signing = SigningKey::generate(&mut rng);
    let did_public_key_multibase =
        arkret_core::ed25519_pubkey_to_did_key_multibase(&did_signing.verifying_key().to_bytes());
    let update_public_key_multibase = arkret_core::ed25519_pubkey_to_did_key_multibase(
        &update_signing.verifying_key().to_bytes(),
    );
    let version_time = SystemClock::default().now();

    let body = signed_starid_create_body(
        host,
        options.port,
        &path,
        &path_segments,
        &did_public_key_multibase,
        &update_public_key_multibase,
        &update_signing,
        version_time,
    )?;

    let admin_token =
        service_id_admin_token(options.admin_token.as_deref(), &options.admin_token_env);
    let endpoint_segments = if admin_token.is_some() {
        &["_starid", "admin", "dids"][..]
    } else {
        &["_starid", "webvh", "dids"][..]
    };
    let endpoint = join_starid_endpoint(&options.starid_url, endpoint_segments)?;
    let mut request = coauth_backend::reqwest_client()
        .post(endpoint.clone())
        .json(&body);
    if let Some(token) = admin_token.as_ref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send_traced()
        .await
        .with_context(|| format!("could not call starid service DID endpoint {endpoint}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        bail!("starid service DID creation failed ({status}): {body}");
    }

    let response_body: Value =
        serde_json::from_slice(&bytes).context("starid response was not valid JSON")?;
    let did = response_body
        .get("did")
        .and_then(Value::as_str)
        .context("starid response did not include a string `did` field")?
        .to_owned();

    write_service_id_key_bundle(
        options.key_output.as_path(),
        &ServiceIdKeyBundle {
            service_id: &did,
            starid_url: options.starid_url.as_str(),
            host,
            path: &path,
            created_at: version_time,
            did_public_key_multibase: &did_public_key_multibase,
            did_key_seed_multibase: &signing_seed_multibase(&did_signing),
            update_public_key_multibase: &update_public_key_multibase,
            update_key_seed_multibase: &signing_seed_multibase(&update_signing),
        },
    )
    .await?;

    let public_output = service_id_public_output(
        options.output,
        &did,
        options.key_output.as_path(),
        &response_body,
    )?;
    write_output(&public_output, None).await?;
    Ok(ExitCode::SUCCESS)
}

fn normalize_service_id_path(path: &str) -> anyhow::Result<String> {
    let path = path.trim().trim_matches('/');
    if path.is_empty() {
        bail!("--path must include at least one non-empty segment");
    }
    Ok(path.to_owned())
}

fn webvh_path_segments(path: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            bail!("--path must not contain empty segments");
        }
        if segment.contains(char::is_whitespace) || segment.contains(':') {
            bail!("--path segments must not contain whitespace or ':'");
        }
        out.push(segment.to_owned());
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn signed_starid_create_body(
    host: &str,
    port: Option<u16>,
    path: &str,
    path_segments: &[String],
    did_public_key_multibase: &str,
    update_public_key_multibase: &str,
    update_signing: &SigningKey,
    version_time: DateTime<Utc>,
) -> anyhow::Result<Value> {
    let document_patch = json!({
        "verificationMethod": {
            "did-key-1": did_public_key_multibase,
        }
    });
    let skeleton =
        webvh_inception_skeleton(update_public_key_multibase, &document_patch, version_time);
    let scid = webvh_derive_scid(&skeleton)?;
    let did = webvh_did(&scid, host, port, path_segments);
    let mut entry = webvh_substitute_scid(skeleton, &scid);
    let entry_hash = webvh_entry_hash_multibase(&entry, &scid)?;
    if let Value::Object(map) = &mut entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{entry_hash}")),
        );
    }

    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "authentication",
        "verificationMethod": format!("{did}#{update_public_key_multibase}"),
    });
    let payload = eddsa_jcs_2022_signing_input(&proof_config, &entry)?;
    let signature = update_signing.sign(&payload);
    let mut proof = proof_config;
    proof["proofValue"] = json!(arkret_core::encode_multibase_base58btc(
        signature.to_bytes()
    ));

    Ok(json!({
        "host": host,
        "port": port,
        "path": path,
        "did_public_key_multibase": did_public_key_multibase,
        "update_public_key_multibase": update_public_key_multibase,
        "did_key_id": "did-key-1",
        "update_key_id": "update-key-1",
        "version_time": version_time,
        "proof": proof,
    }))
}

fn webvh_inception_skeleton(
    update_public_key_multibase: &str,
    document_patch: &Value,
    version_time: DateTime<Utc>,
) -> Value {
    json!({
        "versionId": SCID_PLACEHOLDER,
        "versionTime": version_time,
        "parameters": {
            "method": WEBVH_METHOD_VERSION,
            "scid": SCID_PLACEHOLDER,
            "updateKeys": [update_public_key_multibase],
            "portable": false,
        },
        "state": document_patch,
    })
}

fn webvh_derive_scid(skeleton: &Value) -> anyhow::Result<String> {
    let mut preimage = skeleton.clone();
    if let Value::Object(map) = &mut preimage {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(SCID_PLACEHOLDER.to_owned()),
        );
    }
    let canonical = arkret_core::canonical::canonical_json_bytes(&preimage)
        .context("could not canonicalize webvh SCID preimage")?;
    Ok(sha256_multihash_base58btc(&canonical))
}

fn webvh_substitute_scid(mut value: Value, scid: &str) -> Value {
    let Value::Object(map) = &mut value else {
        return value;
    };
    if let Some(Value::String(version_id)) = map.get_mut("versionId") {
        *version_id = version_id.replace(SCID_PLACEHOLDER, scid);
    }
    if let Some(parameters) = map.get_mut("parameters").and_then(Value::as_object_mut)
        && let Some(Value::String(parameter_scid)) = parameters.get_mut("scid")
    {
        *parameter_scid = parameter_scid.replace(SCID_PLACEHOLDER, scid);
    }
    value
}

fn webvh_entry_hash_multibase(entry: &Value, prev_anchor: &str) -> anyhow::Result<String> {
    let canonical =
        arkret_core::canonical::canonical_json_bytes(&webvh_strip_for_hash(entry, prev_anchor))
            .context("could not canonicalize webvh entry hash preimage")?;
    Ok(sha256_multihash_base58btc(&canonical))
}

fn webvh_strip_for_hash(entry: &Value, prev_anchor: &str) -> Value {
    let mut clone = entry.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(prev_anchor.to_owned()),
        );
    }
    clone
}

fn eddsa_jcs_2022_signing_input(proof_config: &Value, entry: &Value) -> anyhow::Result<Vec<u8>> {
    let mut proof_config = proof_config.clone();
    if let Value::Object(map) = &mut proof_config {
        map.remove("proofValue");
    }
    let mut document = entry.clone();
    if let Value::Object(map) = &mut document {
        map.remove("proof");
    }

    let proof_config_bytes = arkret_core::canonical::canonical_json_bytes(&proof_config)
        .context("could not canonicalize webvh proof config")?;
    let document_bytes = arkret_core::canonical::canonical_json_bytes(&document)
        .context("could not canonicalize webvh proof document")?;
    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&Sha256::digest(&proof_config_bytes));
    signing_input.extend_from_slice(&Sha256::digest(&document_bytes));
    Ok(signing_input)
}

/// Bare base58btc sha256 multihash — no multibase `z` prefix, per DIF
/// did:webvh v1.0 (SCIDs and entry hashes are 46-char `Qm…` strings).
fn sha256_multihash_base58btc(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    arkret_core::encode_base58btc(&multihash)
}

fn webvh_did(scid: &str, host: &str, port: Option<u16>, path_segments: &[String]) -> String {
    let mut out = format!("did:webvh:{scid}:{host}");
    if let Some(port) = port {
        out.push_str("%3A");
        out.push_str(&port.to_string());
    }
    for segment in path_segments {
        out.push(':');
        out.push_str(segment);
    }
    out
}

fn service_id_admin_token(inline: Option<&str>, env_name: &str) -> Option<String> {
    inline
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            coauth_config::runtime_var(env_name)
                .ok()
                .map(|token| token.trim().to_owned())
                .filter(|token| !token.is_empty())
        })
}

fn join_starid_endpoint(base: &Url, segments: &[&str]) -> anyhow::Result<Url> {
    let mut url = base.clone();
    {
        let mut path_segments = url
            .path_segments_mut()
            .map_err(|()| anyhow!("--starid-url must be a hierarchical URL"))?;
        path_segments.pop_if_empty();
        path_segments.extend(segments.iter().copied());
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

struct ServiceIdKeyBundle<'a> {
    service_id: &'a str,
    starid_url: &'a str,
    host: &'a str,
    path: &'a str,
    created_at: DateTime<Utc>,
    did_public_key_multibase: &'a str,
    did_key_seed_multibase: &'a str,
    update_public_key_multibase: &'a str,
    update_key_seed_multibase: &'a str,
}

async fn write_service_id_key_bundle(
    dest: &Utf8Path,
    bundle: &ServiceIdKeyBundle<'_>,
) -> anyhow::Result<()> {
    let yaml = serde_yaml_ng::to_string(&json!({
        "service_id": bundle.service_id,
        "starid_url": bundle.starid_url,
        "host": bundle.host,
        "path": bundle.path,
        "created_at": bundle.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "did_public_key_multibase": bundle.did_public_key_multibase,
        "did_key_seed_multibase": bundle.did_key_seed_multibase,
        "update_public_key_multibase": bundle.update_public_key_multibase,
        "update_key_seed_multibase": bundle.update_key_seed_multibase,
    }))?;

    info!("Writing private service DID key bundle to {dest:?}");
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest.as_std_path())
        .await
        .with_context(|| {
            format!(
                "could not create private service DID key bundle at {dest}; refusing to overwrite"
            )
        })?;
    file.write_all(yaml.as_bytes()).await?;
    Ok(())
}

fn signing_seed_multibase(signing: &SigningKey) -> String {
    arkret_core::encode_multibase_base58btc(signing.to_bytes())
}

fn service_id_public_output(
    output: ServiceIdOutput,
    did: &str,
    key_output: &Utf8Path,
    response_body: &Value,
) -> anyhow::Result<String> {
    match output {
        ServiceIdOutput::Yaml => Ok(serde_yaml_ng::to_string(&json!({
            "arkret": {
                "service_id": did,
            }
        }))?),
        ServiceIdOutput::Did => Ok(format!("{did}\n")),
        ServiceIdOutput::Json => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({
                "service_id": did,
                "key_output": key_output.as_str(),
                "starid_response": response_body,
            }))?
        )),
    }
}

/// Write `content` to the given file path, or to stdout when no path is given.
async fn write_output(content: &str, dest: Option<&Utf8Path>) -> anyhow::Result<()> {
    if let Some(path) = dest {
        info!("Writing configuration to {path:?}");
        let mut file = tokio::fs::File::create(path.as_std_path()).await?;
        file.write_all(content.as_bytes()).await?;
    } else {
        info!("Writing configuration to standard output");
        tokio::io::stdout().write_all(content.as_bytes()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_dev_config_delegates_did_resolution_to_soland() {
        let mut config = RootConfig::test();
        let options = GenerateOptions {
            output: None,
            dev: true,
            service_id: None,
            public_base: None,
            database_uri: None,
        };

        apply_generated_config_options(&mut config, &options)
            .expect("dev config options should apply");

        let registry = config
            .arkret
            .identity_registry
            .expect("dev config should include an identity resolver");
        assert!(matches!(
            registry.kind,
            IdentityRegistryKind::PublicDidResolver
        ));
        assert_eq!(registry.resolver.as_str(), DEV_SOLAND_IDENTITY_RESOLVER_URL);
    }
}
