#!/usr/bin/env bash
# Installs the NIST-compatible OSCAL validator used as our correctness gate.
# oscal-cli is a Java tool; requires JDK 17+ (we test on Temurin 21).
set -euo pipefail
VERSION="3.2.0"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/tools/oscal-cli"
URL="https://repo1.maven.org/maven2/dev/metaschema/oscal/oscal-cli-enhanced/${VERSION}/oscal-cli-enhanced-${VERSION}-oscal-cli.zip"

if [ -x "$DEST/bin/oscal-cli" ]; then
  echo "oscal-cli already installed at $DEST"; exit 0
fi
command -v java >/dev/null || { echo "ERROR: Java 17+ required (brew install --cask temurin)"; exit 1; }
echo "Downloading oscal-cli ${VERSION}..."
tmp="$(mktemp -d)"
curl -sSL -o "$tmp/oscal-cli.zip" "$URL"
mkdir -p "$DEST"
unzip -q -d "$DEST" "$tmp/oscal-cli.zip"
chmod +x "$DEST/bin/oscal-cli"
rm -rf "$tmp"
"$DEST/bin/oscal-cli" --version | head -2
