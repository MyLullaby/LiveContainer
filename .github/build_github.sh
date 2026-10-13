#!/bin/bash
set -euo pipefail

# Fixed historical payload, independent of expiring Actions artifacts and moving nightly releases.
curl --fail --location --retry 3 \
  https://github.com/MyLullaby/LiveContainer/releases/download/1.0/sidestore-base-20260926.ipa \
  --output sidestore-base.ipa
test ! -e Payload
cp -R "$archive_path.xcarchive/Products/Applications" Payload
zip -qry current-lc.ipa Payload -x '._*' '*/.DS_Store' '__MACOSX/*'
python3 .github/package_ipas.py current-lc.ipa sidestore-base.ipa "$scheme"
