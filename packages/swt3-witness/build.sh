#!/bin/bash
# Build the SWT3 Witness container image.
#
# Usage:
#   ./build.sh              # builds ghcr.io/tenova-labs/swt3-witness:0.5.8
#   ./build.sh 0.5.9        # builds with custom tag
#
# Prerequisites:
#   npm install && npm run build   (compile TypeScript first)
#
# Why a build script? BuildKit's git-aware context filter respects
# .gitignore, which blocks node_modules/, dist/, and *.tgz from the
# Docker build context. This script stages runtime files into a clean
# temp directory outside the git tree to bypass that filter.

set -euo pipefail

TAG="${1:-0.5.8}"
IMAGE="ghcr.io/tenova-labs/swt3-witness:${TAG}"
DIR="$(cd "$(dirname "$0")" && pwd)"
STAGE=$(mktemp -d)

trap 'rm -rf "$STAGE"' EXIT

# Stage only runtime files -- no source, no devDeps
cp "$DIR/Dockerfile" "$STAGE/"
cp "$DIR/package.json" "$STAGE/"
cp -r "$DIR/dist" "$STAGE/dist"

# Production-only node_modules: SDK runtime only (no tests, source, devDeps)
# -L dereferences symlinks (npm file: deps create symlinks)
mkdir -p "$STAGE/node_modules/@tenova/swt3-ai"
cp -rL "$DIR/node_modules/@tenova/swt3-ai/dist" "$STAGE/node_modules/@tenova/swt3-ai/dist"
cp -L "$DIR/node_modules/@tenova/swt3-ai/package.json" "$STAGE/node_modules/@tenova/swt3-ai/package.json"
if [ -d "$DIR/node_modules/@tenova/swt3-ai/templates" ]; then
  cp -rL "$DIR/node_modules/@tenova/swt3-ai/templates" "$STAGE/node_modules/@tenova/swt3-ai/templates"
fi

echo "Building $IMAGE from staged context..."
docker build --no-cache -t "$IMAGE" "$STAGE"

SIZE=$(docker image inspect "$IMAGE" --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1048576}')
echo ""
echo "Built: $IMAGE ($SIZE)"
echo "  docker run --rm $IMAGE"
echo "  docker push $IMAGE"
