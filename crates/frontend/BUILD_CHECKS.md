# Frontend build and browser checks

The account UI uses the local Glory and Sapid workspaces. Run commands from the
Coauth root with Cargo, temporary files, and npm caches on D:.

```powershell
$env:CARGO_TARGET_DIR = 'D:/BuildCache/coauth-glory/target'
$env:CARGO_HOME = 'D:/BuildCache/cargo'
$env:TEMP = $env:TMP = 'D:/BuildCache/coauth-glory/tmp'
cargo metadata --no-deps --format-version 1
cargo +nightly fmt -p coauth-frontend --check
cargo test -p coauth-frontend --lib
python scripts/build-frontend.py --release
```

The build script produces `target_directory/web` and matches wasm-bindgen to
Cargo.lock. `--out-dir dist` creates the deployment directory. The static host
loads `/assets/bootstrap.js`, `/assets/pkg/coauth_frontend.js`, its WASM file,
and the Sapid/application stylesheets. Fluent en/zh catalogs are embedded in the
WASM module by `src/translations.rs`.

Serve the web directory with SPA fallback, then run the fixture browser suite:

```powershell
$env:npm_config_cache = 'D:/BuildCache/coauth-glory/npm'
npm --prefix crates/frontend ci --ignore-scripts
$env:COAUTH_TEST_URL = 'http://127.0.0.1:4183'
npm --prefix crates/frontend test
node crates/frontend/tests/smoke.cjs
```

`tests/fixtures.cjs` supplies populated typed API responses and records every
request. The regression suite covers authentication, registration, recovery,
profile/avatar upload, session actions, passkeys, notifications, authorization,
client translations, sign-out, and deactivation gates. It fails on missing
fixture requests, uncaught browser errors, and semantic rendering failures.
Screenshots and machine-readable results are written below the ignored
`artifacts/glory-migration` directory. `tests/csp.cjs` compares the saved old
host on port 4182 with the new host under the configured strict CSP.

The fixtures verify browser behavior and request contracts. Live delivery,
WebAuthn hardware, and OAuth callbacks require configured service integration.
