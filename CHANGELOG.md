# Changelog

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