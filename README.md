# nix-sigman

Simple tool for managing signatures of Nix NAR files when not part of the central
nix cache (i.e. for a static caching server configuration.)

Supports filesystem and S3 backends for all cache operations via [afero](github.com/spf13/afero).

This allows efficiently managing binary caches which may be backed onto S3 stores.
Credential are read from your environment, and so should be as available as they are
to Nix.