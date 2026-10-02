![GitHub License](https://img.shields.io/github/license/wrouesnel/nix-sigman)
[![Build and Test](https://github.com/wrouesnel/nix-sigman/actions/workflows/integration.yml/badge.svg)](https://github.com/wrouesnel/nix-sigman/actions/workflows/integration.yml)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/nix-sigman/badge.svg?branch=main)](https://coveralls.io/github/wrouesnel/nix-sigman?branch=main)
![GitHub Release](https://img.shields.io/github/v/release/wrouesnel/nix-sigman)

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
  --public-keys "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" \
  --private-key-files "/path/to/my-private-key.key" \
  proxy --signing-map "cache.nixos.org-1=my-private-key" /some/root
```

It is also supported to require multiple signatures by using the `&` specifier:

```bash
nix-sigman \
  --public-key-files "/path/to/public.key" \
  --public-key-files "/path/to/other-public.key" \
  --private-key-files "/path/to/my-private-key.key" \
  proxy --signing-map "cache.nixos.org-1&my-other-public-key=my-private-key" /
```

Key options (`--public-keys`, `--public-key-files`, `--private-keys`, `--private-key-files`)
are global and go before the subcommand. Resigning options such as `--signing-map` belong
to the subcommand and go after it.

### Unsigned Resigning

`--unsigned-resigning-keys` specifies a list of keys which will be used to sign NARs which
have _no_ other signatures on them at all - i.e. they have never been signed. This only
takes effect with `--allow-unsigned-resigning`.

An empty public key specifier in the signing map (e.g. `--signing-map "=my-private-key"`)
also matches only unsigned packages. It is rejected unless `--allow-unsigned-resigning`
is given.

`--unconditional-resigning-keys` specifies a list of keys which will be used to sign _every_
NAR file, regardless of what signatures are present. This only takes effect with
`--allow-unconditional-resigning`.

Both of these obviously constitute a potential security hazard, but can be very useful
when dealing with certain situations, which is why they must be explicitly enabled.

## Using Nix HTTP Binary Cache Support

`nix-http-cache` support has been experimentally added. Similar to S3 mode, in this mode
`nix-sigman` talks directly to a Nix HTTP binary cache and can execute most operations
against it. Specify via `--fs-backend=nix-http-cache` and pass the URL as an `--fs-opt`
parameter such as `--fs-opt=https://cache.nixos.org`.

For private repositories you can add a comma separated parameter `netrc-file` to provide
credentials e.g. `--fs-opt=https://my.private.server,netrc-file=/etc/nix/netrc`.

Note: fs-opt configuration in this circumstance is parsed internally as a single-line CSV file.

## Serve mode

Serve mode provides a powerful way to serve a binary cache from an existing `/nix/store`
including if the store itself is not under the actual path `/nix/store` - i.e. for serving
from a snapshotted ZFS filesystem.

### Pushing to a serve mode cache

With `--push-enabled`, serve mode also accepts uploads from `nix copy --to http://...`,
unpacking them into the store and registering them in the Nix database as Nix itself
would when substituting. When `--root` (or `--store-root`) points at a store mounted
somewhere other than `/nix/store`, files are written under the mounted location while
the database records the logical `--store-path`. The store and database must be writable
by the server; it refuses to start otherwise. Pushed paths must have all their
references already present (which `nix copy` ensures by uploading in dependency order).

```
nix-sigman serve --root=/mnt/cache --push-enabled --push-password-file=/etc/nix-sigman/passwd
nix copy --netrc-file ~/.config/nix/netrc --to http://cache.example.com:8081 ./result
```

At least one authentication method is required. Nix clients authenticate with Basic
authentication from a netrc file, so every backend can be used with them:

* **Password files** (`--push-password-file`, repeatable): lines of `username:argon2-hash`.
  Generate a line with `echo -n "$password" | nix-sigman debug hash-password --username alice`.
* **LDAP** (`--push-ldap-url`, `--push-ldap-user-base-dn`, `--push-ldap-group-dn`, ...):
  users are found with `--push-ldap-user-filter`, authenticated by binding as them, and
  must be a member of one of the push groups (checked with `--push-ldap-group-filter`,
  which by default matches `member`, `uniqueMember` and `memberUid`). Users with valid
  credentials who aren't in a push group get `403 Forbidden`.
* **Kerberos** (`--push-kerberos-keytab`): accepts SPNEGO (`Negotiate`) from clients which
  support it, and with `--push-kerberos-basic-auth` validates Basic credentials against
  the KDC (requires `--push-kerberos-service-principal`; the service ticket is verified
  against the keytab so a spoofed KDC can't be used). Principals are authorized by
  `--push-kerberos-allowed-principal` glob patterns (e.g. `*@EXAMPLE.COM`, which doesn't match instances such as `alice/admin@EXAMPLE.COM`) and/or LDAP
  group membership with `--push-kerberos-ldap-authorization`.

Successful Basic logins are cached for `--push-auth-cache-ttl` since the backends are slow
to query. Reads never require authentication.

Nix caches the narinfo it uploads and later fetches the NAR from the URL it uploaded it
under, so the server records those URLs in `--push-index` (by default
`nix/var/nix-sigman/push-index.sqlite` under the root) and serves the NARs there,
recompressed on the fly. The index is still used if the server is later run without push.

Signatures in pushed narinfo files are recorded as-is; `--required-signatures` still
applies when serving. Build logs, `.ls` listings, realisations and debug info uploads are
accepted but discarded. Pushing doesn't take part in Nix's garbage collector root
protocol, so avoid running `nix-collect-garbage` on the store while pushes are in progress.

#### Resigning rules

Pushing users can be allowed to have the server sign what they push with its own private
keys (`--private-keys` or `--private-key-files`). Enable it with an ACL file naming who may sign with which
keys:

```yaml
# /etc/nix-sigman/rules-acl.yml
admins:                     # may list and delete everyone's rules
  users: [root]
  ldap_groups: ["cn=cache-admins,ou=groups,dc=example,dc=com"]
grants:
  - users: [ci-*]           # glob patterns, matched against the authenticated username
    keys: [release-*]       # glob patterns of loaded private key names
  - ldap_groups:
      - cn=release,ou=groups,dc=example,dc=com
    keys: [release-1]
```

Quote LDAP DNs in YAML flow lists (`[...]`), since otherwise the commas split them apart.
`ldap_groups` requires LDAP to be configured; Kerberos principals are looked up by their
primary name. Grants are rechecked whenever a rule is applied, so revoking a grant (or
unloading a key) stops existing rules signing with it.

```
nix-sigman --private-key-files=/etc/nix-sigman/release-1.sec serve --root=/mnt/cache \
  --push-enabled --push-password-file=/etc/nix-sigman/passwd \
  --push-rules-acl-file=/etc/nix-sigman/rules-acl.yml --push-rules-max-ttl=24h
```

Rules are managed with the same credentials used to push, under `/_sigman/rules`, and are
stored in `--push-rules-db` (by default `nix/var/nix-sigman/rules.sqlite` under the root):

```
# Sign this user's pushes of hello-* that aren't already signed, for the next 2 hours.
curl --netrc-file netrc -X POST http://cache.example.com:8081/_sigman/rules -d '{
  "description": "release 2.12",
  "condition": {"and": [{"name": "hello-*"}, {"not": {"signed_by": "release-1"}}]},
  "sign_with": ["release-1"],
  "expires_in": "2h"
}'
curl --netrc-file netrc http://cache.example.com:8081/_sigman/rules
curl --netrc-file netrc -X DELETE http://cache.example.com:8081/_sigman/rules/<id>
# Delete every rule signing with a key (admins: add owner=<user> to limit it to one user).
curl --netrc-file netrc -X DELETE 'http://cache.example.com:8081/_sigman/rules?sign_with=release-1'
```

| Request | |
|---|---|
| `GET /_sigman/rules[?owner=&sign_with=]` | List unexpired rules. |
| `POST /_sigman/rules` | Create a rule owned by the caller. Returns `201` with the rule. |
| `GET /_sigman/rules/<id>` | Get a rule. |
| `DELETE /_sigman/rules/<id>` | Delete a rule. |
| `DELETE /_sigman/rules[?owner=&sign_with=]` | Delete matching rules. Admins must give a filter or `all=true`. |

Users only see and delete their own rules; admins can manage everyone's, but still need a
grant to create rules. A rule only applies to paths its owner pushes, so nobody can get
another user's uploads signed with keys that user hasn't been granted.

A rule's `condition` is optional (if omitted it matches every path) and has exactly one
of these operators:

* `{"and": [...]}`, `{"or": [...]}`, `{"not": {...}}`
* `{"signed": true|false}`: whether the path has any signatures.
* `{"signed_by": "key-name"}`: whether the path has a valid signature by a public key from
  `--public-key-files` or the public half of a loaded private key.
* `{"name": "glob"}`: matched against the store path name without its hash, e.g. `hello-*`
  matches `/nix/store/<hash>-hello-2.12`.

Rules can expire, given either `expires_in` (a duration like `90m`) or `expires_at`
(RFC 3339). `--push-rules-max-ttl` limits how long rules may last and is the default expiry
for rules which don't give one. Expired rules stop applying immediately and are removed
from the database.

Signatures are added as paths are pushed and stored in the Nix database, so they remain
after the rule is deleted or expires. Nix doesn't upload paths the cache already has, so
a new rule doesn't sign paths pushed before it was created; sign those on the server with
`nix store sign --store local?root=/mnt/cache --key-file <key> <paths>`.
