# Changelog

## 1.0.0 (2026-10-18)


### Features

* encrypted chunked attachments in the storage layer ([c8de502](https://github.com/SudhirDevOps1/vaultnote/commit/c8de502a274a84f0f14acc1907d80c8c2edc9d6e))


### Bug Fixes

* let release-please own one manifest instead of three ([14a27a5](https://github.com/SudhirDevOps1/vaultnote/commit/14a27a5e69cf0cc6d5164b28014f08f8f63b37a3))
* name the chunk type clippy called too complex ([#3](https://github.com/SudhirDevOps1/vaultnote/issues/3)) ([87078c2](https://github.com/SudhirDevOps1/vaultnote/commit/87078c23cf6d8483debb93acc093d44d06d7f196))
* repair the release workflow and validate workflows in CI ([#6](https://github.com/SudhirDevOps1/vaultnote/issues/6)) ([83c8046](https://github.com/SudhirDevOps1/vaultnote/commit/83c804670be3c3acd767dc9e23da3e8f0f209f12))
* stop release-please proposing 1.0.0, and refuse non-prerelease tags ([#5](https://github.com/SudhirDevOps1/vaultnote/issues/5)) ([e35f368](https://github.com/SudhirDevOps1/vaultnote/commit/e35f368363aec879fa99c3b94fba3f4ec6bbe1e9))
* three type errors in the attachment layer ([0ab16a2](https://github.com/SudhirDevOps1/vaultnote/commit/0ab16a2e07448ed64c5f0314608c140e279c0d2c))
* unblock the IPC boundary, and make a green build produce a downloadable installer ([#8](https://github.com/SudhirDevOps1/vaultnote/issues/8)) ([effe256](https://github.com/SudhirDevOps1/vaultnote/commit/effe25611616994d7d22c0a6c3d11bf3623f35fd))

## Changelog

All notable changes to Vaultnote are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is generated and maintained by
[release-please](https://github.com/googleapis/release-please) from
[conventional commits](https://www.conventionalcommits.org/). Do not edit it by
hand — edit the commit messages instead.

Versions are written to `package.json`, `src-tauri/Cargo.toml` and
`src-tauri/tauri.conf.json` together, and the release workflow refuses to build
if those three disagree with the tag.

## Pre-1.0 status

The project is **pre-release and unverified as an application**. The crypto
core is verified by tests; the application has never been built into a binary
or launched. Do not put real notes in it yet.

### Verified

- Argon2id and XChaCha20-Poly1305 byte-for-byte against vectors produced by
  libsodium (via PyNaCl) and the PHC reference C implementation (via
  argon2-cffi). This is a cross-implementation check, not a self-test.
- The AEAD authenticates associated data, verified against libsodium's own
  published vector.
- `vault.db` and its WAL contain no plaintext. Checked by planting known
  markers, searching the raw bytes, and separately proving those markers are
  still readable through the API — so absence means encryption, not data loss.
- Wrong password and vault corruption produce an identical error string.
- Idle auto-lock, password change re-wrapping without re-encrypting bodies.

### Not done

- The app has never been compiled to a binary or run.
- Attachments, encrypted export/import, Markdown rendering.
- No code signing, so installers will trigger SmartScreen.
- No recovery. Lose the master password and the data is gone.

### Known limitations

- A dependency bump can change cryptographic output with no code change. The
  KAT suite will fail loudly if that happens; that is the intended behaviour.
- Search decrypts every note. That is the cost of not indexing ciphertext.
- Metadata leaks: row counts, sizes and timestamps are visible in the database
  file. Titles, bodies and tags are not.
