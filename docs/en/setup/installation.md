# Installation

## Pre-built binaries

Pre-built binaries can be found attached on each release, for Linux on both `x86_64` and `aarch64` architectures.

- [`coauth-aarch64-linux.tar.gz`](https://github.com/arkret-org/coauth/releases/latest/download/coauth-aarch64-linux.tar.gz)
- [`coauth-x86_64-linux.tar.gz`](https://github.com/arkret-org/coauth/releases/latest/download/coauth-x86_64-linux.tar.gz)

Each archive contains:

- the `coauth` binary
- assets needed for running the service, including:
  - `share/assets/`: the built frontend assets
  - `share/manifest.json`: the manifest for the frontend assets
  - `share/cedar/`: the Cedar policy files
  - `share/templates/`: the default templates
  - `share/translations/`: the default translations

The location of all these assets can be overridden in the [configuration file](../reference/configuration.md).

---

Example shell commands to download and extract the `coauth` binary:

```sh
ARCH=x86_64 # or aarch64
OS=linux
VERSION=latest # or a specific version, like "v0.1.0"

# URL to the right archive
URL="https://github.com/arkret-org/coauth/releases/${VERSION}/download/coauth-${ARCH}-${OS}.tar.gz"

# Create a directory and extract the archive in it
mkdir -p /path/to/mas
curl -sL "$URL" | tar xzC /path/to/mas

# This should display the help message
/path/to/mas/coauth --help
```


## Using the Docker image

A pre-built Docker image is available here: [`ghcr.io/arkret-org/coauth:latest`](https://ghcr.io/arkret-org/coauth:latest)

The `latest` tag is built using the latest release.
The `main` tag is built from the `main` branch, and each commit on the `main` branch is also tagged with a stable `sha-<commit sha>` tag.

The image can also be built from the source:

1. Get the source
   ```sh
   git clone https://github.com/arkret-org/coauth.git
   cd coauth
   ```
1. Build the image
   ```sh
   docker build -t mas .
   ```

## Building from the source

Building from the source requires:

- The latest stable [Rust toolchain](https://www.rust-lang.org/learn/get-started)
- [Node.js (18 and later)](https://nodejs.org/en/) and [npm](https://www.npmjs.com/get-npm)

1. Get the source
   ```sh
   git clone https://github.com/arkret-org/coauth.git
   cd coauth
   ```
1. Build the frontend
   ```sh
   cd frontend
   npm ci
   npm run build
   cd ..
   ```
   This will produce a `dist` directory containing the built frontend assets.
   This folder, along with the `dist/manifest.json` file, can be relocated, as long as the configuration file is updated accordingly.
1. Compile the CLI
   ```sh
   cargo build --release
   ```
1. Grab the built binary
   ```sh
   cp ./target/release/coauth ~/.local/bin # Copy the binary somewhere in $PATH
   coauth --help # Should display the help message
   ```

## Next steps

The service needs deployment configuration and a durable KeyStore backend.
Private keys are provisioned into that backend rather than written into YAML.
Follow the [configuration guide](./general.md) to configure the service.
