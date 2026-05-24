# Frontend Build Checks

## Fluent Catalog Bundle

The Dioxus SPA embeds the current Fluent catalogs from:

- `translations/en.ftl`
- `translations/zh.ftl`

`src/translations.rs` includes both files with `include_str!`, and
`src/main.rs` renders them into a hidden `application/json` script with
`id="coauth-fluent-bundles"`. This keeps the `dx build` output tied to the
same en+zh catalogs that the backend loads through `coauth-i18n`.

`Dioxus.toml` watches `../../translations` so local `dx serve` sessions reload
when either catalog changes.

## Local Check

```powershell
Push-Location crates/frontend
dx build --release --platform web
Pop-Location

$buildRoots = @("dist", "crates/frontend/dist", "target/dx", "crates/frontend/target/dx") |
  Where-Object { Test-Path $_ }
rg -a -n 'coauth-account-locked-heading|账户已锁定|coauth-fluent-bundles' $buildRoots
```

Expected result: the build succeeds, and the grep finds the English Fluent key,
the Chinese translation text, and the `coauth-fluent-bundles` canary in the
generated assets.

If the local Rust workspace is blocked by a sibling SDK version mismatch, run
the `rg -a` check against the most recent local `dist/` after recording the
Cargo resolver error in the task notes.
