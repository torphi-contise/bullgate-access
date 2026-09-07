#!/bin/sh
set -eu

if [ -n "${BULLGATE_MASTER_KEY_FILE:-}" ]; then
  if [ ! -s "$BULLGATE_MASTER_KEY_FILE" ]; then
    echo "Bullgate master key is missing: $BULLGATE_MASTER_KEY_FILE" >&2
    exit 1
  fi

  Bullgate__MasterKey="$(cat "$BULLGATE_MASTER_KEY_FILE")"
  export Bullgate__MasterKey
fi

exec dotnet Bullgate.Access.Api.dll
