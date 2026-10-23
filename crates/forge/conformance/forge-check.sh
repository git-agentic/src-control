#!/usr/bin/env bash
# Run `run.py check` against the in-tree sc-forge: bootstrap an empty data dir the way
# Engine does (admin CLI), start the server on a free loopback port, check, stop.
# Usage: forge-check.sh [extra run.py check args]   (CI runs it with none)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
# Offline: the fixture writer round-trips and every stored fixture is in canonical compact form.
python3 -I "$here/run.py" selftest
cargo build --quiet --manifest-path "$root/Cargo.toml" -p scl-forge
bin="${CARGO_TARGET_DIR:-$root/target}/debug/sc-forge"
data="$(mktemp -d)"
pid=""
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf "$data"; }
trap cleanup EXIT
"$bin" admin user create --data-dir "$data" --username siteadmin --password "$(openssl rand -hex 16)" \
  --email admin@example.invalid --admin --must-change-password=false >/dev/null
token="$("$bin" admin user generate-access-token --data-dir "$data" --username siteadmin --token-name conformance --scopes all --raw)"
port="$(python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
"$bin" serve --data-dir "$data" --listen "127.0.0.1:$port" --public-url "http://127.0.0.1:$port" 2>"$data/serve.log" &
pid=$!
for _ in $(seq 50); do
  python3 -I -c "import urllib.request as u;u.urlopen('http://127.0.0.1:$port/api/healthz')" 2>/dev/null && break
  sleep 0.1
done
python3 -I "$here/run.py" check --base-url "http://127.0.0.1:$port" --admin-token "$token" \
  --fixtures "$here/fixtures/1.22.6" --departures "$here/departures.json" --pending "$here/slice-pending.json" \
  --only A,B "$@" || { echo "--- server log"; cat "$data/serve.log"; exit 1; }
