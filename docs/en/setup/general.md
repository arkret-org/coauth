# General configuration

## Generate an initial config

The service needs signing keys, an encryption secret, database settings, and
Cokret deployment metadata before it can start.

Use the generator to produce a complete config file with defaults:

```sh
coauth config generate > config.yaml
```

The generated file is intentionally verbose. In practice you usually keep the
sections you override and remove the untouched defaults.

## Sections you will almost always edit

- `http.public_base`
- `database`
- `cokret.principal_servers`
- `cokret.identity_registry`
- `cokret.service_did`
- `cokret.issuer_did`
- `cokret.admin_audience`
- `secrets`
- `passwords`

## Validate the config

```sh
coauth config check --config=config.yaml
```

## Inspect the merged result

```sh
coauth config dump --config=config.yaml
```

Multiple config files can be layered. The lookup order is:

1. Every file passed with `--config`
2. Otherwise the `COAUTH_CONFIG` environment variable, split by `:`
3. Otherwise `config.yaml` in the current working directory

Environment overrides use the `COAUTH_` prefix and `__` as the nesting
separator. For example:

```sh
COAUTH_EMAIL__PROVIDER__TYPE=resend
COAUTH_EMAIL__PROVIDER__API_KEY=re_xxxxxxxxx
```

## Editor schema

The generated JSON schema lives at `docs/config.schema.json`. You can regenerate
it from the current Rust config model with:

```sh
cargo run -p coauth-config --bin schema > docs/config.schema.json
```

In VS Code or other YAML-aware editors, point the file at that schema:

```yaml
# yaml-language-server: $schema=./docs/config.schema.json
```

## Sync config-backed database state

Some sections are synchronized into the database on startup, especially:

- `clients`
- `upstream_oauth`

You can sync them manually with:

```sh
coauth config sync
```

Add `--prune` if removed entries should also be deleted from the database.
