#!/bin/sh
set -eu

: "${BULLGATE_BOOTSTRAP_MANIFEST:?BULLGATE_BOOTSTRAP_MANIFEST is required}"
: "${BULLGATE_MASTER_KEY_FILE:?BULLGATE_MASTER_KEY_FILE is required}"
: "${BULLGATE_INTEGRATION_CREDENTIAL_FILE:?BULLGATE_INTEGRATION_CREDENTIAL_FILE is required}"
: "${BULLGATE_INTEGRATION_CLIENT_PATH:?BULLGATE_INTEGRATION_CLIENT_PATH is required}"

master_key_file="$BULLGATE_MASTER_KEY_FILE"
credential_file="$BULLGATE_INTEGRATION_CREDENTIAL_FILE"
credential_path_file="$credential_file.path"
temporary_result="$(mktemp)"

umask 077
mkdir -p "$(dirname "$master_key_file")" "$(dirname "$credential_file")"
trap 'rm -f "$temporary_result"' EXIT

if [ ! -s "$master_key_file" ]; then
  master_key="$(head -c 32 /dev/urandom | base64)"
  printf '%s' "$master_key" > "$master_key_file"
fi

Bullgate__MasterKey="$(cat "$master_key_file")"
export Bullgate__MasterKey

dotnet /tools/migrations/Bullgate.Access.Migrations.dll
dotnet /tools/cli/Bullgate.Access.Cli.dll \
  bootstrap --manifest "$BULLGATE_BOOTSTRAP_MANIFEST" > "$temporary_result"

resolve_resource_id() {
  wanted_type="$1"
  wanted_path="$2"
  awk -v wanted_type="$wanted_type" -v wanted_path="$wanted_path" '
    /^[[:space:]]*"type":/ {
      type = $0
      sub(/^[^:]*:[[:space:]]*"/, "", type)
      sub(/".*/, "", type)
      path = ""
      id = ""
      next
    }
    /^[[:space:]]*"path":/ {
      path = $0
      sub(/^[^:]*:[[:space:]]*"/, "", path)
      sub(/".*/, "", path)
      next
    }
    /^[[:space:]]*"id":/ {
      id = $0
      sub(/^[^:]*:[[:space:]]*"/, "", id)
      sub(/".*/, "", id)
      if (type == wanted_type && path == wanted_path) {
        print id
        exit
      }
    }
  ' "$temporary_result"
}

integration_client_id="$(resolve_resource_id integrationClient "$BULLGATE_INTEGRATION_CLIENT_PATH")"
if [ -z "$integration_client_id" ]; then
  echo "Bootstrap output did not contain integration client '$BULLGATE_INTEGRATION_CLIENT_PATH'." >&2
  exit 1
fi

issued_token="$(awk -v wanted_path="$BULLGATE_INTEGRATION_CLIENT_PATH" '
  /^[[:space:]]*"integrationClientPath":/ {
    path = $0
    sub(/^[^:]*:[[:space:]]*"/, "", path)
    sub(/".*/, "", path)
    selected = path == wanted_path
    next
  }
  selected && /^[[:space:]]*"token":/ {
    token = $0
    sub(/^[^:]*:[[:space:]]*"/, "", token)
    sub(/".*/, "", token)
    print token
    exit
  }
' "$temporary_result")"

if [ -n "$issued_token" ]; then
  printf '%s' "$issued_token" > "$credential_file"
  printf '%s' "$BULLGATE_INTEGRATION_CLIENT_PATH" > "$credential_path_file"
elif [ ! -s "$credential_file" ]; then
  echo "Bootstrap found integration client '$BULLGATE_INTEGRATION_CLIENT_PATH', but its credential volume is missing." >&2
  echo "Reset the Access PostgreSQL and integration credential volumes together before starting this demo stack again." >&2
  exit 1
elif [ ! -s "$credential_path_file" ] \
    || [ "$(cat "$credential_path_file")" != "$BULLGATE_INTEGRATION_CLIENT_PATH" ]; then
  echo "The stored integration credential does not identify '$BULLGATE_INTEGRATION_CLIENT_PATH'." >&2
  echo "Reset the Access PostgreSQL and integration credential volumes together before starting this demo stack again." >&2
  exit 1
fi

chmod 0444 "$master_key_file"
chmod 0444 "$credential_file"
chmod 0444 "$credential_path_file"

echo "Bullgate Access migrations and topology are ready."
