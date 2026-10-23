#!/usr/bin/env bash
# Start a throwaway Gitea container and print BASE_URL=... ADMIN_TOKEN=... CONTAINER=...
# Usage: gitea-up.sh <version> <label>    e.g. gitea-up.sh 1.22.6 rec
# Name and host port are random, so parallel runs never collide.
set -euo pipefail
ver="${1:?usage: gitea-up.sh <version> <label>}"
label="${2:?usage: gitea-up.sh <version> <label>}"
image="gitea/gitea:${ver}-rootless"
name="sc-forge-conf-${label//[^A-Za-z0-9_.-]/-}-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
pass="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

# Pick a free host port, then let Docker bind it; retry if someone raced us.
started=0
err=""
for _ in 1 2 3 4 5; do
  port="$(python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
  if err="$(docker run -d --name "$name" -p "127.0.0.1:${port}:3000" \
    -e GITEA__database__DB_TYPE=sqlite3 \
    -e GITEA__security__INSTALL_LOCK=true \
    -e GITEA__service__DISABLE_REGISTRATION=true \
    -e GITEA__actions__ENABLED=false \
    -e GITEA__server__DISABLE_SSH=true \
    -e "GITEA__server__ROOT_URL=http://127.0.0.1:${port}/" \
    -e GITEA__service__REQUIRE_SIGNIN_VIEW=true \
    -e GITEA__repository__DEFAULT_PRIVATE=private \
    -e GITEA__repository__FORCE_PRIVATE=true \
    -e GITEA__server__OFFLINE_MODE=true \
    "$image" 2>&1)"; then
    started=1
    break
  fi
  # Only a lost port race is worth retrying; anything else (missing image, daemon down) is fatal.
  docker rm -f "$name" >/dev/null 2>&1 || true
  case "$err" in
    *"port is already allocated"*|*"address already in use"*|*"ports are not available"*) ;;
    *) echo "docker run failed for $image: $err" >&2; exit 1 ;;
  esac
done
[ "$started" = 1 ] || { echo "could not start $image after retries: $err" >&2; exit 1; }
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' ERR

base="http://127.0.0.1:${port}"
ready=0
for _ in $(seq 1 120); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$base/api/healthz" || true)"
  if [ "$code" = 200 ]; then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "gitea did not become ready" >&2
  docker logs "$name" 2>&1 | tail -20 >&2
  docker rm -f "$name" >/dev/null 2>&1 || true
  exit 1
fi

docker exec "$name" gitea admin user create --admin --username siteadmin --password "$pass" \
  --email admin@example.invalid --must-change-password=false >/dev/null
token="$(docker exec "$name" gitea admin user generate-access-token --username siteadmin --scopes all --raw | tr -d '\r\n')"
echo "BASE_URL=${base} ADMIN_TOKEN=${token} CONTAINER=${name}"
