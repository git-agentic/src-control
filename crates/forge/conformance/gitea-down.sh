#!/usr/bin/env bash
# Remove a container made by gitea-up.sh. Refuses any name it did not create.
set -euo pipefail
c="${1:?usage: gitea-down.sh <container>}"
case "$c" in
  sc-forge-conf-*) ;;
  *) echo "refusing: $c is not a sc-forge-conf container" >&2; exit 2 ;;
esac
docker rm -f "$c" >/dev/null
