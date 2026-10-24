#!/usr/bin/env bash
# Smoke test of the sc-forge image: it starts, answers /healthz, git is new enough, a repository
# can be created and cloned, and `docker stop` ends it with exit code 0 (the SIGTERM drain).
# Usage: smoke.sh <image>
set -euo pipefail
image=${1:?usage: smoke.sh <image>}
name=sc-forge-smoke-$$
port=${SMOKE_PORT:-13000}
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; docker volume rm -f "$name-data" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run --rm --entrypoint git "$image" --version
docker volume create "$name-data" >/dev/null
docker run --rm -v "$name-data:/data" "$image" admin user create --data-dir /data \
  --username siteadmin --password "$(head -c 24 /dev/urandom | base64)" \
  --email admin@example.invalid --admin --must-change-password=false >/dev/null
token=$(docker run --rm -v "$name-data:/data" "$image" admin user generate-access-token --data-dir /data \
  --username siteadmin --token-name smoke --scopes all --raw)
docker run -d --name "$name" -v "$name-data:/data" -p "127.0.0.1:$port:3000" "$image" serve \
  --data-dir /data --listen 0.0.0.0:3000 --behind-proxy --public-url "http://127.0.0.1:$port" >/dev/null

for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$port/api/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$port/api/healthz" >/dev/null
curl -fsS -H "Authorization: token $token" -H 'Content-Type: application/json' \
  -d '{"name":"smoke","auto_init":true}' "http://127.0.0.1:$port/api/v1/user/repos" >/dev/null
work=$(mktemp -d)
git clone -q "http://siteadmin:$token@127.0.0.1:$port/siteadmin/smoke.git" "$work/smoke"
test -f "$work/smoke/README.md"
rm -rf "$work"

docker stop -t 40 "$name" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$code" = 0 ] || { echo "sc-forge exited with $code after SIGTERM" >&2; docker logs "$name" >&2; exit 1; }
echo "smoke ok"
