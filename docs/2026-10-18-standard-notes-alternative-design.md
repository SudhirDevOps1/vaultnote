# Design: Standard Notes Alternative — "Vaultnote"

**Date:** 2026-10-18
**Status:** Awaiting approval — kuch bhi build nahi hua hai abhi tak
**Location:** `D:\reverse eng\`

---

## 1. Intent aur "kyun"

Standard Notes ek E2EE (end-to-end encrypted) notes app hai. Is project ka maqsad hai uska **local-only** version banana — jisme server **bilkul exist na karta**.

Core reasoning: Standard Notes ka asli security model yeh hai ki *server sirf ciphertext dekhta hai, encryption client pe hoti hai.* Server hata do, woh property aur zyada strong ho jaati hai — **koi doosra system hi nahi hai jismein data leak ho sake.** Yeh architecture choice hai, shortcut nahi.

**User ka requirement (apne shabdon mein):**
> "data server pe nahi jaana, sab kuch locally save hona chahiye"

---

## 2. Scope

### Karenge (Goals)

| # | Feature | Kyun zaroori |
|---|---|---|
| G1 | Master-password se unlock, AES/XChaCha encryption | Core — bina iske yeh app nahi hai |
| G2 | Note create / edit / delete / trash | Core |
| G3 | Local encrypted search (title + body) | Notes app ka basic expectation |
| G4 | Tags | Standard Notes ka signature feature |
| G5 | Markdown editor + preview | Notes likhne ka natural tareeqa |
| G6 | Encrypted file attachments (images etc.) | SN ismein bhi allow karta hai |
| G7 | Encrypted export/import (portable backup) | Data ka koi aur raasta hona chahiye |
| G8 | Auto-lock on idle + clipboard auto-clear | Security hygiene |
| G9 | Dark/light theme | Standard |

### Nahi karenge (Non-goals) — **by design**

| # | Feature | Reason |
|---|---|---|
| N1 | Sync server | User ne explicitly kaha: local only. Server = scope ka dushman. |
| N2 | Mobile app | Phase 1 me out of scope. Architecture aise banega ki baad me add ho sake. |
| N3 | Multi-user / sharing | Local app me meaningless hai |
| N4 | Payment / subscription | Not applicable |
| N5 | Extensions / components marketplace | SN ka differentiator hai, par local app me overkill |

### Anti-goals (yeh "fail" hai agar aisa hua)

- ❌ Master key **kabhi bhi JavaScript (webview) me na jaye** — sirf Rust process memory me
- ❌ Plaintext **kabhi bhi disk pe plain nahi jaye** — DB file 100% ciphertext
- ❌ Password recovery ka koi backdoor
- ❌ "Encryption hai" claim bina test ke — har crypto step ka test hoga

---

## 3. Constraints (machine par kya hai — verified)

Ye maine actually check kiya hai, guess nahi:

| Tool | Status | Note |
|---|---|---|
| CPU | **i5-6300U, 2 physical / 4 logical cores, 15W TDP** | 2016 ultrabook laptop. **Yeh sabse binding constraint hai.** |
| RAM | 7.9 GB | |
| Node.js v24.19.0 | ✅ | |
| pnpm 12.10.1 | ✅ | |
| MSVC 14.44.35207 | ✅ | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools` |
| Windows SDK 10.0.26100.0 | ✅ | Rust ko chahiye Tauri build ke liye |
| Rust 1.99.1 | ✅ | Phase 0 me install kiya |

### 3.1 Thermal constraint — yeh build ko govern karta hai

Cargo ka default behaviour har logical core pe ek job chalana hai. 2-core
ultrabook pe iska matlab hai **sustained all-core load**, jo thermal limit tak
pahunchata hai — aur first build ke dauraan machine ne **shut down hone ki
koshish ki**. Ye target ki galti nahi, toolchain ki default behaviour ki galti
hai.

Isliye teen rules project me **enforced** hain, sirf documented nahi:

| Rule | Kahan enforce hua hai |
|---|---|
| `jobs = 2` — 4 logical core pe bhi max 2 parallel jobs | `src-tauri/.cargo/config.toml` |
| `debug = 0` — debug info generation skip, cold build halka | `src-tauri/Cargo.toml` `[profile.dev]` |
| Load ceiling + auto-abort | `scripts/build-safe.ps1` — 85% sustained 4 samples pe build kill |

**Iska asar planning pe:** release build (`tauri build`, LTO + `opt-level="s"` +
`codegen-units = 1`) is machine pe **nahi chalana**. Verification `cargo dev`
profile pe hogi, packaging nahi. Ek successful build ke baad incremental
changes seconds me compile hote hain, to cost ek hi baar hota hai.

### 3.2 pnpm 12 build-script approval

pnpm 12 ne `onlyBuiltDependencies` hatayi aur `allowBuilds` map laayi. Vite ke
liye esbuild ka postinstall approve karna padta hai, warna install
`ERR_PNPM_IGNORED_BUILDS` pe fail hota hai. Explicitly likha gaya hai —
`dangerouslyAllowAllBuilds` jaan-boojh kar nahi lagaya, kyunki woh blanket
approval hai aur is project me sirf ek package approve karna tha.

### 3.3 Database driver: rusqlite, not tauri-plugin-sql

Design me tauri-plugin-sql socha gaya tha. Build se pata chala ki woh
`sqlx-postgres`, `sqlx-mysql`, `sqlx-sqlite`, `borsh` aur `rust_decimal`
drag laata hai — **~150 extra crates sirf ek plugin ki wajah se**, aur yeh
machine pe compile hi nahi ho paa rahe the.

`rusqlite` (bundled) par switch kiya. Sirf compile time bachega nahi, security
boundary bhi saaf hoti hai: database ko webview ko dekar padhna hi nahi padta,
aur Phase 5 me attachments IPC ke through stream nahi honge.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────┐
│  Webview (React + TypeScript)                       │
│  ┌───────────────────────────────────────────┐      │
│  │  Editor UI — sirf DISPLAY karta hai       │      │
│  │  Plaintext yahan RAM me hota hai           │      │
│  │  ★ Master key YAHAN KABHI NAHI AATI ★      │      │
│  └───────────────────────────────────────────┘      │
└──────────────────────┬──────────────────────────────┘
                       │  Tauri IPC (invoke)
                       │  plaintext jaata hai, key nahi
┌──────────────────────▼──────────────────────────────┐
│  Rust Process — "The Vault"                         │
│  ┌───────────────────────────────────────────┐      │
│  │ SessionManager                            │      │
│  │   root_key: Mutex<Option<[u8;32]>>        │      │
│  │   - zeroize on lock / crash / timeout     │      │
│  └───────────────────────────────────────────┘      │
│  ┌───────────────────────────────────────────┐      │
│  │ Crypto Engine                            │      │
│  │   - Argon2id   (password -> root key)     │      │
│  │   - XChaCha20-Poly1305 (encrypt/decrypt)  │      │
│  │   - Envelope key wrapping                 │      │
│  └───────────────────────────────────────────┘      │
└──────────────────────┬──────────────────────────────┘
                       │  cipher text only
┌──────────────────────▼──────────────────────────────┐
│  SQLite  →  D:\reverse eng\vaultnote\vault.db      │
│  100% ciphertext. Koi plaintext column nahi.        │
└─────────────────────────────────────────────────────┘
```

### Sabse important design decision: key ka kahan rehna hai

Do options the:

**Option A** — Key webview (JavaScript Web Crypto) me.
**Option B** — Key sirf Rust me, webview ko sirf decrypted data jata hai.

**Chuna: Option B.** Reasons:
- Webview sabse bada attack surface hai — koi XSS/devtools/browser-extension key nikal sakta hai
- Rust side ka memory boundary tight hai
- Webview crash/close hone se key gayab ho jaati hai (auto-secure)

Iska matlab: **har decrypt operation Rust me hota hai**, aur IPC ke through plaintext aata hai. Disk pe jaane se pehle sab encrypt.

---

## 5. Encryption design (detailed)

Standard Notes ka model improve karke **envelope encryption** use karenge:

```
STEP 1 — Master key derivation (login ke baad, ek hi baar)
    root_key = Argon2id(
        password   = user ka master password,
        salt       = random 16 bytes, DB me store (yeh secret NAHI hai),
        ops_limit  = 3,
        mem_cost   = 64 MB,
        out_len    = 32 bytes
    )

STEP 2 — Har note ke liye apni key (note banate waqt, ek baar)
    data_key = random 32 bytes

STEP 3 — Note encrypt
    nonce          = random 24 bytes
    ciphertext     = XChaCha20Poly1305(data_key, nonce, plaintext_json)

STEP 4 — data_key ko wrap karo (taaki password change ho sake)
    wrapped_key    = XChaCha20Poly1305(root_key, random_nonce, data_key)
    → yeh DB me jata hai
```

**Isse kya milta hai:**
- Ek note decrypt karne ke liye sirf uski `data_key` chahiye
- **Password change = sirf `wrapped_key` dobara wrap karo** — saare notes dobara encrypt nahi karne padte
- Ek corrupt note se baaki notes safe rehte hain

**Crypto parameters** (in `Cargo.toml`):

```toml
argon2          = "0.5"    # Argon2id
chacha20poly1305 = "0.10"  # XChaCha20-Poly1305
rand            = "0.8"    # CSPRNG
zeroize         = "1.8"    # memory wipe
```

**Test vector requirement:** NIST/RFC test vectors se verify karna hoga ki implementation sahi hai — self-written test se khud ko validate karna invalid hai.

---

## 6. Data model (SQLite)

```sql
-- Master metadata. NOTE: koi bhi secret yahan nahi.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- keys: 'schema_version', 'argon2_salt', 'created_at',
--       'kdf_params_json', 'auto_lock_seconds'

-- Sab kuch ciphertext
CREATE TABLE items (
    id            TEXT    PRIMARY KEY,   -- uuid v4
    content_type  TEXT    NOT NULL,      -- 'note' | 'attachment' (yeh metadata leak hoti hai — jaan-boojh kar)
    nonce         BLOB    NOT NULL,      -- 24 bytes
    wrapped_key   BLOB    NOT NULL,      -- root_key se wrapped data_key
    wrap_nonce    BLOB    NOT NULL,      -- 24 bytes
    ciphertext    BLOB    NOT NULL,      -- actual encrypted payload
    created_at    INTEGER NOT NULL,      -- unix ms
    updated_at    INTEGER NOT NULL,
    deleted_at    INTEGER               -- NULL = alive, ms = in trash
);

CREATE TABLE attachments (
    id         TEXT PRIMARY KEY,
    item_id    TEXT NOT NULL REFERENCES items(id),
    meta_ct    BLOB NOT NULL,   -- encrypted {filename, mime, size}
    data_ct    BLOB NOT NULL    -- encrypted file bytes (chunked)
);

CREATE INDEX idx_items_alive    ON items(deleted_at);
CREATE INDEX idx_items_updated  ON items(updated_at);
```

**Note ka andar kya hai (JSON, encrypt hua):**
```json
{
  "title": "...",
  "text": "# markdown content",
  "tags": ["personal", "urgent"],
  "attachments": ["uuid1", "uuid2"],
  "pinned": false
}
```

**Search kaise hoga:** ciphertext pe search possible nahi. Toh decrypt-all → in-memory filter. 10,000 notes tak comfortably chalta hai. Indexing nahi banayi — kyunki index khud encrypted DB me leak ho jayega.

---

## 7. Tech stack

| Layer | Choice | Reason |
|---|---|---|
| Shell | **Tauri v2** | Chhota binary (~5MB vs Electron ~150MB), Rust backend native hai |
| Frontend | React 19 + TypeScript + Vite | Type safety, standard tooling |
| Backend | Rust | Crypto correctness + memory safety |
| DB | SQLite (Tauri `sql` plugin, `rusqlite`) | Local file, zero setup |
| State | Zustand | Lightweight, no boilerplate |
| Editor | CodeMirror 6 (Markdown) | Built-in markdown, fast, mobile-friendly |

**Kyun Electron nahi:** 150 MB install, 300 MB RAM. Tauri ke peeche wahi Node/React frontend hai, par shell 10x halka.

---

## 8. Milestones

Har milestone ke end pe **verify hona chahiye** — "compile hua" nahi, "actually kaam karta hai".

### Phase 0 — Setup (30 min)
- [ ] `rustup-init.exe` install karo (MSVC toolchain select karke)
- [ ] `cargo --version` verify
- [ ] Tauri v2 project scaffold
- [ ] **Gate:** blank app build hoke khule, screenshot lo

### Phase 1 — Crypto core (2-3 hrs) ⭐ Sabse important
- [ ] `crypto.rs` — Argon2id + XChaCha20-Poly1305 + key wrapping
- [ ] NIST/RFC test vectors se verify
- [ ] Round-trip tests: encrypt → decrypt → same bytes?
- [ ] Wrong-password pe decrypt fail hona chahiye (error leakage nahi)
- [ ] `zeroize` verify — memory wipe ho raha hai
- [ ] **Gate:** `cargo test` green, test vectors pass

### Phase 2 — Storage (2 hrs)
- [ ] SQLite schema + migrations
- [ ] CRUD commands (`list`, `get`, `save`, `delete`, `purge`)
- [ ] `dex_classdiff`-style structural verification nahi chahiye, but: **DB file me plaintext grep karo — zero matches hona chahiye**
- [ ] **Gate:** DB file ki bytes inspect karke proof ki koi plaintext nahi hai

### Phase 3 — Session + UI (3-4 hrs)
- [ ] Unlock screen (Argon2id chalta hai — spinner dikhana zaroori, 64MB mem cost me time lagta hai)
- [ ] SessionManager + auto-lock (idle timeout)
- [ ] Note list + editor + live save
- [ ] Trash (soft delete)
- [ ] **Gate:** app kholo, note likho, band karo, dobara kholo — note mojood hai

### Phase 4 — Search + Tags (1-2 hrs)
- [ ] Decrypt-all → in-memory search
- [ ] Tag create/filter
- [ ] **Gate:** 100+ fake notes generate karke search latency measure karo

### Phase 5 — Attachments (2-3 hrs)
- [ ] Chunked encrypt/decrypt (bade files RAM me nahi aayenge)
- [ ] Image preview
- [ ] **Gate:** 50MB file add karo, restart karo, verify content match

### Phase 6 — Export/Import (1-2 hrs)
- [ ] Encrypted `.vaultnote` bundle (ek file, poori DB + attachments)
- [ ] Import = naye password se re-wrap
- [ ] **Gate:** export → wipe → import → data identical

### Phase 7 — Polish (1-2 hrs)
- [ ] Dark/light theme
- [ ] Clipboard auto-clear (30s)
- [ ] Window blur pe auto-lock
- [ ] Error states (wrong password, DB corrupt, disk full)

---

## 9. Security checklist (har milestone pe verify)

- [ ] DB file me `strings` / grep → **zero plaintext matches**
- [ ] Master key webview me nahi jaati (DevTools se confirm)
- [ ] Lock hone pe `root_key` zeroized
- [ ] Wrong password → generic error, "kitne characters sahi hain" type leak nahi
- [ ] Auto-lock idle pe
- [ ] Clipboard 30s baad clear
- [ ] App kill hone pe WAL/temp files me ciphertext hi hai

---

## 10. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Rust install fail / MSVC version clash | Low | MSVC 14.44 + SDK 26100 confirmed present |
| Tauri WebView2 missing | Medium | Windows 11 pe by default hota hai; check karenge |
| Argon2id 64MB RAM pe slow lage | Low | Intentional hai — yeh password brute-force slow karta hai |
| Bade attachments memory me bhar jaayein | Medium | Chunked streaming Phase 5 me |
| Scope creep (mobile/sync add karne ka mann kare) | High | Non-goals list explicitly likhi hai — usse review karte waqt dekhna |

---

## 11. Builder ke liye open decisions

Ye cheezein main decide kar sakta hoon (defaults diye hain), par aap bata sakte ho:

1. **App ka naam** — maine "Vaultnote" rakha hai. Aapka pasand nahi hai to badal denge.
2. **Argon2id memory cost** — 64 MB (OWASP recommendation). Kam = faster unlock, zyada = zyada secure. Default 64 MB.
3. **Auto-lock timeout** — default 5 minutes idle.
4. **First-run flow** — koi account nahi. Bas "master password set karo" screen. Koi recovery nahi — agar bhool gaye to data gaya. **Yeh jaan-boojh kar choose kiya gaya hai** (account recovery = backdoor).

---

## 12. Kya is plan ke baad banega

```
D:\reverse eng\
├── docs\
│   └── 2026-10-18-standard-notes-alternative-design.md   ← yeh file
├── vaultnote\                    ← app code
│   ├── src-tauri\               ← Rust backend (crypto, db, session)
│   └── src\                     ← React frontend (editor, list)
├── vaultnote\vault.db           ← aapka encrypted data (Phase 2 ke baad)
└── .agents\skills\apk-reverse\  ← pehle wala skill, untouched
```