#!/bin/sh
# One user-initiated install; interactive setup reads the terminal, not this pipe.
main() {
  set -eu
  repository='gosuda/teatime'
  hub_url=''
  web_url=''
  tls_pin=''
  architecture=''
  for argument in "$@"; do
    case "$argument" in
      --hub-url=* ) hub_url=${argument#*=} ;;
      --web-url=* ) web_url=${argument#*=} ;;
      --tls-pin=* ) tls_pin=${argument#*=} ;;
      --architecture=* ) architecture=${argument#*=} ;;
      *) printf '%s\n' 'Use --hub-url=URL, --architecture=amd64|arm64.' >&2; return 1 ;;
    esac
  done
  dev_http=0
  if [ -n "$tls_pin" ]; then
    if ! printf '%s\n' "$tls_pin" | LC_ALL=C grep -Eq '^[a-fA-F0-9]{64}$' || [ "${hub_url#https://}" = "$hub_url" ]; then printf '%s\n' 'Invalid Hub TLS pin.' >&2; return 1; fi
  fi
  if [ -n "$web_url" ]; then
    web_url=${web_url%/}
    if ! printf '%s\n' "$web_url" | LC_ALL=C grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$'; then
      if printf '%s\n' "$web_url" | LC_ALL=C grep -Eq '^http://(127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?$'; then dev_http=1
      else printf '%s\n' 'Public website requires HTTPS.' >&2; return 1; fi
    fi
  fi
  if [ -n "$hub_url" ]; then
    hub_url=${hub_url%/}
    # Accept only an origin with a literal, safe hostname/port. No shell eval.
    if ! printf '%s\n' "$hub_url" | LC_ALL=C grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$'; then
      if printf '%s\n' "$hub_url" | LC_ALL=C grep -Eq '^http://(127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?$'; then dev_http=1
      else printf '%s\n' 'Hub requires an HTTPS origin; HTTP is allowed only for literal loopback QA.' >&2; return 1; fi
    fi
    # curl | sh consumes stdin; make sure setup can still ask for device input.
    if ! ( : </dev/tty ) 2>/dev/null; then printf '%s\n' 'Run this command from an interactive terminal for device setup.' >&2; return 1; fi
  fi
  case "$(uname -s)" in Linux) platform=linux;; Darwin) platform=darwin;; *) printf '%s\n' 'Unsupported OS; use the PowerShell installer on Windows.' >&2; return 1;; esac
  if [ -z "$architecture" ]; then
    case "$(uname -m)" in x86_64|amd64) architecture=amd64;; aarch64|arm64) architecture=arm64;; *) printf '%s\n' 'Unsupported architecture.' >&2; return 1;; esac
  fi
  case "$architecture" in amd64|arm64) ;; *) printf '%s\n' 'Unsupported architecture.' >&2; return 1;; esac
  destination=${HUBCONN_INSTALL_DIR:-"$HOME/.local/bin"}
  asset="hubconn_${platform}_${architecture}"
  location=$(curl --proto '=https' --tlsv1.2 -fsSL --max-time 60 -o /dev/null -w '%{url_effective}' "https://github.com/$repository/releases/latest")
  tag=${location##*/}
  case "$tag" in ''|*[!A-Za-z0-9._-]*) printf '%s\n' 'Invalid release tag.' >&2; return 1;; esac
  base="https://github.com/$repository/releases/download/$tag"
  staging=$(mktemp -d)
  trap 'rm -f "$staging/$asset" "$staging/SHA256SUMS"; rmdir "$staging"' EXIT
  trap 'exit 1' HUP INT TERM
  curl --proto '=https' --tlsv1.2 -fsSL --max-time 60 "$base/SHA256SUMS" -o "$staging/SHA256SUMS"
  verify_asset() {
    verify_name=$1
    curl --proto '=https' --tlsv1.2 -fsSL --max-time 180 "$base/$verify_name" -o "$staging/$verify_name"
    expected=$(awk -v name="$verify_name" '$2==name {print $1; count++} END {if (count!=1) exit 1}' "$staging/SHA256SUMS")
    if ! printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[a-fA-F0-9]{64}$'; then printf '%s\n' 'Invalid release checksum.' >&2; return 1; fi
    if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$staging/$verify_name"); else actual=$(shasum -a 256 "$staging/$verify_name"); fi
    actual=${actual%% *}
    expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
    if [ "$actual" != "$expected" ]; then printf '%s\n' 'Release checksum mismatch.' >&2; return 1; fi
    if command -v gh >/dev/null 2>&1; then gh attestation verify "$staging/$verify_name" -R "$repository"
    else printf 'Release provenance: gh attestation verify %s -R %s\n' "$verify_name" "$repository"; fi
  }
  verify_asset "$asset"
  # Verify the Connector before installation begins.
  mkdir -p "$destination"
  install -m 755 "$staging/$asset" "$destination/.hubconn-install-$$"
  mv -f "$destination/.hubconn-install-$$" "$destination/hubconn"
  printf 'Installed hubconn %s. Install gjl separately from https://gjl.io/ before service setup.\n' "$tag"
  if [ -z "$hub_url" ]; then printf 'Next: %s/hubconn setup https://YOUR-HUB\n' "$destination"; return; fi
  set -- setup "$hub_url" --profile installed --purpose register
  if [ -n "$web_url" ]; then set -- "$@" --web-url "$web_url"; fi
  if [ -n "$tls_pin" ]; then set -- "$@" --tls-pin "$tls_pin"; fi
  if [ "$dev_http" -eq 1 ]; then set -- "$@" --dev-http; fi
  if ! "$destination/hubconn" "$@" </dev/tty; then printf '%s\n' 'Device setup did not finish. The programs remain installed; run hubconn setup again.' >&2; return 1; fi
  printf 'Device registration complete. Next: %s/hubconn run, then continue use or provide setup in My devices on the website.\nFor later terminals: export PATH="%s:$PATH"\n' "$destination" "$destination"
}
main "$@"
