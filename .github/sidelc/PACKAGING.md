# Preserved SideStore payload

The upstream SideStore IPA and dylibify release URLs are unavailable. Packaging
uses the already converted SideStore components from this repository's successful
run `36206537707`, artifact `10893649917`, commit
`a0f6d2d4f2d83fb8d570106cd8770f962792148a` (2026-09-26).

The original combined IPA is preserved as the `sidestore-base-20260926.ipa`
asset on this repository's `1.0` release. Its SHA-256 is pinned in
`../package_ipas.py`:

`0e1014344b40fe03996c07b8c55221f708b964f22d5087f40b864e6beea53da3`

SideStore version: `0.7.0-20260918.492+12a496ca`, build `0700`.
Only SideStoreApp.framework, LiveWidgetExtension.appex, and the host intent
definitions/metadata are copied. LiveContainer and SideStoreSupport always come
from the current build. The package must still be signed by the installation tool.

Do not overwrite the preserved asset. To upgrade SideStore, verify a replacement
payload, publish it under a new asset name, and update the URL and checksum together.
