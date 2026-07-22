# Running the service

To fully function, the service needs to run two main components:

 - An HTTP server
 - A background worker

By default, the [`coauth server`](../reference/cli/server.md) command will start both components.
It is possible to only run the HTTP server by setting the `--no-worker` option, and run a background worker with the [`coauth worker`](../reference/cli/worker.md) command.

Both components are stateless, and can be scaled horizontally by running multiple instances of each.

## Runtime requirements

Other than the binary, the service needs a few files to run:

 - The templates, referenced by the [`templates.path`](../reference/configuration.md#templates) configuration option
 - The compiled policy, referenced by the [`policy.path`](../reference/configuration.md#policy) configuration option
 - The frontend assets, referenced by the `path` option of the `assets` resource in the [`http.listeners`](../reference/configuration.md#http) configuration section
 - The frontend manifest file, referenced by the [`templates.assets_manifest`](../reference/configuration.md#templates) configuration option

Be sure to check the [installation instructions](./installation.md) for more information on how to get these files, and make sure the configuration file is updated accordingly.

**If you are using [the docker image](./installation.md#using-the-docker-image)**, everything is already included in the image at the right place, so in most cases you don't need to do anything.

**If you are using [the pre-built binaries](./installation.md#pre-built-binaries)**, those files are shipped alongside them in the `share` directory.
The default configuration will look for them from the current working directory, meaning that you don't have to adjust the paths, as long as you are running the service from the parent directory of the `share` directory.

## Configure the HTTP server

The service can be configured to have multiple HTTP listeners, serving different resources.
See the [`http.listeners`](../reference/configuration.md#http) configuration section for more information.

The service needs to be aware of the public URL it is served on, regardless of the HTTP listeners configuration.
This is done using the [`http.public_base`](../reference/configuration.md#http) configuration option.
By default, the OIDC issuer advertised by the `/.well-known/openid-configuration` endpoint will be the same as the `public_base` URL, but can be configured to be different.

## Tweak the remaining configuration

A few configuration sections might still require some tweaking, including:

 - [`telemetry`](../reference/configuration.md#telemetry): to setup metrics, tracing and Sentry crash reporting
 - [`email`](../reference/configuration.md#email): to setup email sending
 - [`password`](../reference/configuration.md#password): to enable/disable password authentication
 - [`account`](../reference/configuration.md#account): to configure what account management features are enabled
 - [`upstream_oauth`](../reference/configuration.md#upstream-oauth): to configure upstream OAuth providers


## Run the service

Once the configuration is done, the service can be started with the [`coauth server`](../reference/cli/server.md) command:

```sh
coauth server
```

It is advised to run the service as a non-root user, using a tool like [`systemd`](https://www.freedesktop.org/wiki/Software/systemd/) to manage the service lifecycle. A sample unit is provided at [`misc/systemd/coauth.service`](../../../misc/systemd/coauth.service):

```sh
sudo install -m 0644 misc/systemd/coauth.service /etc/systemd/system/coauth.service
sudo systemctl daemon-reload
sudo systemctl enable --now coauth
```

For container deployments see [Running with Docker](./docker.md).


## Liveness / readiness probes

The service exposes `/health`, `/healthz`, and `/readyz` on the internal
listener (default `localhost:8091`). `/health` and `/healthz` return
`200 OK` with body `ok` when the configured Postgres pool is reachable.
`/readyz` also checks that the public JWKS can be materialized from the
configured signing keys.

```sh
curl --fail http://localhost:8091/health
```

In Kubernetes, point `livenessProbe.httpGet.path` at `/healthz` and
`readinessProbe.httpGet.path` at `/readyz` on the internal listener
(see [Running with Docker](./docker.md) for a full example). See
[Observability](../observability.md) for telemetry and Prometheus setup.


## Troubleshoot common issues

Once the service is running, it is possible to check its configuration using the [`coauth doctor`](../reference/cli/doctor.md) command.
This should help diagnose common issues with the service configuration and deployment.


## Development mode

To enable the global development posture and record full server-side error
diagnostics, use:

```sh
COAUTH_DEVELOPMENT_MODE=true coauth server -c config.yaml
```

The equivalent global CLI flag is `--development-mode`. Development mode does
not change HTTP error responses. Test endpoints and insecure development escape
hatches still require their dedicated explicit flags. When `RUST_LOG` is not
set, development mode changes the default log filter to `debug`. Detailed
errors may contain sensitive deployment information, so do not enable it in
production.
