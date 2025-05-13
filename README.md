# nix-sigman

Simple tool for managing signatures of Nix NAR files when not part of the central
nix cache (i.e. for a static caching server configuration.)

Supports filesystem and S3 backends for all cache operations via [afero](github.com/spf13/afero).

This allows efficiently managing binary caches which may be backed onto S3 stores.
Credential are read from your environment, and so should be as available as they are
to Nix.

## Using S3 support

S3 or a compatible store can be accessed by specifying the credentials in your
environment:

```
AWS_ACCESS_KEY_ID=<your key>
AWS_SECRET_ACCESS_KEY=<your secret key>
AWS_REGION=us-east-1
```

Set `AWS_ENDPOINT_URL` or `AWS_ENDPOINT_URL_S3` to use a non-AWS source (like minio):

```
AWS_ENDPOINT_URL=http://127.0.0.1:9000
```

## Server

The resigning server allows more easily implementing trusted resigning schemes, particularly
when used with S3 storage. The server will always serve an object, but if it matches the
supplied re-signing rules then the narinfo file will have additional signatures added
to it when it is returned.

e.g.
```bash
nix-sigman \
  --public-key "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" \
  --private-key-files "/path/to/my-private-key.key" \
  --signing-map "cache.nixos.org-1=my-private-key" proxy /some/root
```

It is also supported to require multiple signatures by using the `&` specifier:

```bash
nix-sigman \
  --public-key-files "/path/to/public.key" \
  --public-key-files "/path/to/other-public.key" \
  --private-key-files "/path/to/my-private-key.key" \
  --signing-map "cache.nixos.org-1&my-other-public-key=my-private-key" proxy /
```

This configuration will only apply the signature if *both* signatures are present
and valid.