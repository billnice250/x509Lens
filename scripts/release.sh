#!/bin/bash
set -euo pipefail

VERSION="${1:?Usage: ./scripts/release.sh v1.0.0}"

git diff --quiet
git diff --cached --quiet

git tag "$VERSION"
git push origin "$VERSION"

make production ARCH=all
make appstore-upload