// Override the embedded git version at build time (useful in CI where the
// full history may not be checked out).
variable "VERGEN_GIT_DESCRIBE" {}

// Default build group — produces both the release and debug images.
group "default" {
  targets = ["release", "debug"]
}

// Metadata targets populated by the CI pipeline.
target "docker-metadata-action" {}
target "docker-metadata-action-debug" {}

// Shared base configuration for all image targets.
target "base" {
  platforms = [
    "linux/amd64",
    "linux/arm64",
  ]

  args = {
    // Keep .git around so the build can run `git describe` if needed.
    BUILDKIT_CONTEXT_KEEP_GIT_DIR = 1

    // Allow CI to inject the version string.
    VERGEN_GIT_DESCRIBE = "${VERGEN_GIT_DESCRIBE}"
  }
}

// Release image (default Dockerfile target).
target "release" {
  inherits = ["base", "docker-metadata-action"]
}

// Debug image (uses the "debug" stage in the Dockerfile).
target "debug" {
  inherits = ["base", "docker-metadata-action-debug"]
  target = "debug"
}
