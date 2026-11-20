#!/bin/sh
# Build the self-hosted bundle in Docker: worker/dist/handscheck-<version>-linux-<arch>.tar.gz.
#   sh worker/packaging/selfhosted/build.sh [amd64|arm64]     (default: Docker's native architecture)
#
# The wheel is built from the `bundle` export (scripts/public/export.py): worker/ with every prompt stripped and
# the rules kept. The finished tarball then has to pass the leak check (scripts/public/check.py), so a release
# can never carry the prompts. In the public repo (no scripts/public/) it builds from worker/ as it is: that tree
# has no prompts to begin with.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
worker=$(cd "$here/../.." && pwd)
root=$(cd "$worker/.." && pwd)
arch=${1:-$(docker version -f '{{.Server.Arch}}')}
case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 2 ;; esac

context=$worker
if [ -f "$root/scripts/public/export.py" ]; then
    mkdir -p "$root/.local"
    (cd "$root" && git ls-files --cached --others --exclude-standard > .local/public-files.txt)
    (cd "$root" && docker compose run --rm -T worker python /repo/scripts/public/export.py --profile bundle \
        --out /repo/.local/bundle-src --files-from /repo/.local/public-files.txt)
    context=$root/.local/bundle-src/worker
fi
rm -f "$worker"/dist/handscheck-*-linux-"$arch".tar.gz
docker buildx build --platform "linux/$arch" -f "$here/Dockerfile" --output "type=local,dest=$worker/dist" "$context"
bundle=$(ls -1 "$worker"/dist/handscheck-*-linux-"$arch".tar.gz)
if [ -f "$root/scripts/public/check.py" ]; then
    name=$(basename "$bundle")
    (cd "$root" && docker compose run --rm -T worker python /repo/scripts/public/check.py --profile bundle \
        "/repo/worker/dist/$name")
fi
echo "$bundle"
