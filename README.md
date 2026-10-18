# Vaultnote

A local-first, end-to-end encrypted notes app — a Standard Notes alternative
with **no server at all**.

The entire point is the absence of a backend. Standard Notes already encrypts
client-side so the server only ever sees ciphertext; removing the server makes
that property unconditional, because there is no second system left to leak to.

- **Design document:** [`docs/2026-10-18-standard-notes-alternative-design.md`](docs/2026-10-18-standard-notes-alternative-design.md)
- **Stack:** Tauri v2 · Rust · SQLite (`rusqlite`) · React 19 · TypeScript

---

## Status

This is an **in-progress build**, not a finished product. What follows is the
honest state of each claim.

| Phase | State | Evidence |
|---|---|---|
| 0 · Toolchain + scaffold | done | Rust 1.99.1, MSVC 14.44, pnpm install clean, frontend builds |
| 1 · Crypto core | **code written, not yet compiled** | 14 tests written in `src-tauri/src/crypto.rs` |
| 2 · Storage | **code written, not yet compiled** | 11 unit tests + 2 leakage tests written |
| 3 · UI | **code written, not yet compiled** | Frontend typechecks; Tauri binary never built |
| 4+ · Search, attachments, export | not started | — |

**No claim in this README is verified by a passing build yet.** The Rust side
has never been compiled. Treat "done" as "written", not "working".

### Known gaps, stated up front

- **No external known-answer tests.** The crypto tests are property-based
  (round-trip, tamper detection, determinism, sensitivity to each KDF input).
  They are *not* checked against RFC 9106 or a libsodium vector. A property
  suite can pass on a subtly wrong implementation; a KAT cannot. This is the
  single most important thing to fix before trusting this app with real notes.
- **No recovery.** Lose the master password and the data is gone. There is no
  reset, no email, no key escrow — deliberately, because every recovery path is
  a decryption path for someone else.
- **No sync, no mobile.** Out of scope by decision (design doc §2).
- **Metadata leaks.** Row count, sizes and update times are visible in the
  database file. Titles, bodies and tags are not.

---

## Security design

### The master key never enters the webview

The webview is the largest attack surface in a Tauri app — XSS, DevTools,
extensions. So key material is handled only in Rust:

```
Rust process                          Disk
───────────                           ────
password ──Argon2id(salt,64MiB)──► root_key
                                      │
      ┌───────────────────────────────┘
      │ per note, per save:
      │   data_key   = CSPRNG 32 bytes
      │   ciphertext = XChaCha20-Poly1305(data_key, nonce, note_json)
      │   wrapped    = XChaCha20-Poly1305(root_key, nonce2, data_key)
      ▼
IPC returns note plaintext only ──► vault.db  (100% ciphertext)
```

`src-tauri/src/commands.rs` is the complete IPC surface. It has **no command
that takes or returns key material** — that is the property to preserve when
adding features.

### Envelope layout

Each note has its own key, wrapped under the root key. Two consequences:

- **Password change re-wraps keys only.** Note bodies are never re-encrypted.
- **One corrupt note cannot affect the others.** They do not share a key.

### Decisions worth knowing about

- **Password check is exact.** First run wraps a fixed verifier constant under
  the root key; unlocking unwraps and compares it. The alternative — "decrypt
  something and see if it fails" — would accept a wrong password with
  probability 2⁻²⁵⁶ and is harder to reason about.
- **Wrong password and a corrupt file produce the same message.** A distinct
  "this vault is damaged" string would be a free oracle for anyone holding the
  file.
- **A fresh data key on every save.** No key is ever reused across two
  encryptions.
- **Every secret is wrapped in `Zeroizing`.** Keys are wiped from memory on
  drop, not left for the allocator to reuse.
- **Search decrypts everything.** Ciphertext cannot be indexed without leaking
  the index. For a local vault this is the right trade.
- **The database never touches the webview.** Queries run in Rust via
  `rusqlite`, so nothing round-trips through JS to be read.

---

## Running it

> The build is throttled on purpose — see below. Expect the first one to be slow.

```powershell
pnpm install

# Recommended on this machine: throttled, with thermal watchdog
.\scripts\build-safe.ps1 -CargoArgs "check --all-targets"

# Once checked, run the app (debug build)
pnpm tauri dev
```

### Tests

```powershell
.\scripts\build-safe.ps1 -CargoArgs "test"
```

The leakage gate is the one that matters most locally:

```powershell
cargo test --test vault_leakage
```

It plants known plaintext markers, writes 25 notes, then searches the raw
bytes of `vault.db` **and its WAL** for every marker — and separately proves
the same markers *are* recoverable through the API, so their absence from disk
means encryption worked rather than data being lost.

---

## Why the build is throttled

This machine is an **i5-6300U**: 2 physical cores, 4 threads, 15W TDP laptop.

`cargo -j 1` alone is **not** sufficient. `-j` limits how many *crates* build
concurrently, but a single `rustc` drives LLVM across every core. Measured here:

| Configuration | Peak CPU |
|---|---|
| default (`-j 4`) | **93%** — machine shut down |
| `-j 2` | 84% |
| `-j 1` | 68–85% |
| `-j 1` + affinity to 2 logical CPUs | see `scripts/build-safe.ps1` |

So the wrapper applies three independent brakes:

1. **Processor affinity** — pins the whole build tree to N logical CPUs.
   Children inherit affinity, so one setting covers cargo, every `rustc`, and
   every `cc`/`link`.
2. **Priority `BelowNormal`** — the build yields to anything else.
3. **Sustained-load watchdog** — samples CPU every 5s; if it stays above the
   ceiling for several consecutive samples the build is killed.

`target/` caches everything, so an interrupted build resumes rather than
restarts.

**Release packaging (`pnpm tauri build`) is not run on this machine** — LTO plus
`opt-level="s"` would be far heavier than a debug build. Verification happens in
the `dev` profile.

---

## Layout

```
vaultnote\
├── README.md
├── docs\2026-10-18-standard-notes-alternative-design.md
├── src\                           React frontend
│   ├── App.tsx                    shell: unlock gate vs notes
│   ├── components\                Unlock, Sidebar, Editor
│   └── lib\api.ts                 the entire typed IPC surface
├── src-tauri\
│   ├── src\crypto.rs              Argon2id, XChaCha20-Poly1305, key wrapping
│   ├── src\db.rs                  SQLite schema + CRUD (ciphertext only)
│   ├── src\vault.rs               crypto ↔ storage glue
│   ├── src\session.rs             root key in memory, idle auto-lock
│   ├── src\commands.rs            IPC surface
│   └── tests\vault_leakage.rs    Phase 2 gate
├── scripts\build-safe.ps1         throttled build wrapper
└── scripts\make_icons.py          icon generation, stdlib only
```