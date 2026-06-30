#!/bin/bash
# garage.toml file for configuring a test garage server
# See: https://stackoverflow.com/questions/59895/how-to-get-the-source-directory-of-a-bash-script-from-within-the-script-itself
# Note: you can't refactor this out: its at the top of every script so the scripts can find their includes.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

# atexit handler
ATEXIT=()

function atexit() {
  ATEXIT+=( "$*" )
}

function _atexit_handler() {
  local EXPR
  for (( idx=${#ATEXIT[@]}-1 ; idx>=0 ; idx-- )); do
    EXPR="${ATEXIT[idx]}"
    echo "atexit: $EXPR" 1>&2
    eval "$EXPR"
  done
}

trap _atexit_handler EXIT

function log() {
  echo "$*" 1>&2
}

function fatal() {
  echo "$*" 1>&2
  exit 1
}

if ! GARAGE_CONFIG_FILE=$(mktemp garage.XXXXXXX.toml); then
  fatal "could not make config file"
fi
export GARAGE_CONFIG_FILE
atexit rm -f "$GARAGE_CONFIG_FILE"

if ! _garage_dir="$(mktemp -d garage.XXXXXX.dir)"; then
  fatal "failed to create directory temporary directory"
fi

if [ -z "${_garage_dir}" ]; then
  fatal "got empty dirname"
fi
atexit rm -rf "${_garage_dir}"

cat > $GARAGE_CONFIG_FILE <<EOF
metadata_dir = "${_garage_dir}/meta"
data_dir = "${_garage_dir}/data"
db_engine = "sqlite"

replication_factor = 1

rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$(openssl rand -hex 32)"

[s3_api]
s3_region = "garage"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"

[s3_web]
bind_addr = "[::]:3902"
root_domain = ".web.garage.localhost"
index = "index.html"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "$(openssl rand -base64 32)"
metrics_token = "$(openssl rand -base64 32)"
EOF

export GARAGE_DEFAULT_ACCESS_KEY="GK$(openssl rand -hex 16)"
export GARAGE_DEFAULT_SECRET_KEY="$(openssl rand -hex 32)"
export GARAGE_DEFAULT_BUCKET="nix-cache"

echo "export AWS_ACCESS_KEY_ID=$GARAGE_DEFAULT_ACCESS_KEY"
echo "export AWS_SECRET_ACCESS_KEY=$GARAGE_DEFAULT_SECRET_KEY"
echo "export AWS_REGION=garage"

garage server --single-node --default-bucket