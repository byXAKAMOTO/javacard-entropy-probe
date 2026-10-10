# Releases: the exact CAP that goes on cards

This folder keeps, per version, the exact `entropyprobe.cap` that is installed on cards that ship: the file itself, not a rebuild. `bin/` is for building and every build overwrites it.

| Version | Source | Component fingerprint | File SHA-256 |
|---|---|---|---|
| [`v1.0`](v1.0/README.md) | `7b06cfe` | `973dfaf417e4cb011b601aa4460ea0651dc3b04385c011585cb23bdf6bfe1fbe` | `b4023220a2cf8d8c3b81ed2ef877ff35dfdd6b5203a12caa821125ac512c413d` |

## The rule

1. **One folder per version that ships**, `vX.Y/` after the package version that `build.sh` gives the converter. Never an intermediate build.
2. **The file goes in as it was installed, not rebuilt.** A CAP is a ZIP with the build time in its manifest, so building the same source again gives another file hash with the same components. The component fingerprint identifies the binary -the SHA-256 of the `*/javacard/*.cap` entries, sorted by path and concatenated- and the file SHA-256 identifies the file. Each version's README gives both.
3. **Nothing here is ever overwritten or deleted.**

`.gitignore` ignores `*.cap` everywhere except here, and `.gitattributes` declares them binary, so git keeps them byte for byte.
