"""Cross-check the Tauri IPC surface: Rust commands vs JS invoke() calls.

Nothing has ever executed this boundary. The Rust command names and the
JavaScript invoke() names were written separately and never compared, so a
single mismatch means the app launches and every button throws.

Tauri v2 converts camelCase argument names from JS to snake_case in Rust, so
`session.with` style naming has to be checked in both forms.

Exits non-zero on any mismatch, so it can run in CI.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST_DIR = ROOT / "src-tauri" / "src"
TS_DIR = ROOT / "src"

# `#[tauri::command] pub fn name(args) -> ...`
CMD_RE = re.compile(
    r"#\[(?:tauri::)?command[^\]]*\]\s*pub\s+(?:async\s+)?fn\s+(\w+)\s*\(([^)]*)\)",
    re.S,
)

# `name: invoke<Ret>("command", { arg: value })`  and  `invoke("command", args)`
INVOKE_RE = re.compile(r"""invoke(?:<[^>]*>)?\(\s*["']([\w_]+)["']""", re.S)

# `{ someArg: value }` or a bare identifier as the second argument
DICT_RE = re.compile(r"\{([^}]*)\}", re.S)
IDENT_ARG_RE = re.compile(r"invoke(?:<[^>]*>)?\(\s*[\"']\w+[\"']\s*,\s*(\w+)")


def to_snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def parse_directives(policy: str) -> dict:
    """Turn `a 'self'; b 'self' c` into {"a": ["'self'"], "b": [...]}."""
    out = {}
    for part in policy.split(";"):
        bits = part.split()
        if bits:
            out[bits[0].lower()] = bits[1:]
    return out


def extract_conf_csp() -> str | None:
    path = ROOT / "src-tauri" / "tauri.conf.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("app", {}).get(
            "security", {}
        ).get("csp")
    except (json.JSONDecodeError, AttributeError):
        return None


def extract_meta_csp() -> str | None:
    path = ROOT / "index.html"
    if not path.is_file():
        return None
    html = path.read_text(encoding="utf-8")
    # The policy value itself contains single quotes, so a character class that
    # excludes both quote types truncates at the first 'self' and reports the
    # meta tag as empty. Match each delimiter separately instead.
    double = re.search(
        r'http-equiv="Content-Security-Policy"[^>]*?content="([^"]+)"', html, re.S
    )
    if double:
        return double.group(1)
    single = re.search(
        r"http-equiv='Content-Security-Policy'[^>]*?content='([^']+)'", html, re.S
    )
    return single.group(1) if single else None


def main() -> int:
    rust = {}
    for f in RUST_DIR.glob("*.rs"):
        text = f.read_text(encoding="utf-8")
        for m in CMD_RE.finditer(text):
            # Strip the injected State/AppHandle parameters before splitting on
            # commas. `State<'_, SessionManager>` contains one, so splitting
            # first leaves an orphan `SessionManager>` that reads like a real
            # parameter and makes every report on this command confusing.
            sig = re.sub(r"State<[^>]*>|AppHandle(?:<[^>]*>)?", "", m.group(2))
            caller_params = [
                p.split(":")[0].strip()
                for p in sig.split(",")
                if p.strip()
            ]
            rust[m.group(1)] = (f.name, caller_params)

    js_calls = {}
    for f in list(TS_DIR.rglob("*.ts")) + list(TS_DIR.rglob("*.tsx")):
        text = f.read_text(encoding="utf-8")
        for name in INVOKE_RE.findall(text):
            js_calls.setdefault(name, []).append(f.name)

    print(f"rust commands : {len(rust)}")
    print(f"js invocations: {len(js_calls)}")
    print()

    problems = []

    only_rust = sorted(set(rust) - set(js_calls))
    only_js = sorted(set(js_calls) - set(rust))

    if only_js:
        print("FAIL js calls a command Rust does not expose:")
        for n in only_js:
            print(f"  {n}  (called from {', '.join(sorted(set(js_calls[n])))})")
        problems += only_js

    if only_rust:
        print("note Rust commands with no caller (not a failure):")
        for n in only_rust:
            print(f"  {n}  ({rust[n]})")
    print()

    # Argument-name check. Handles both `{ a, b }` shorthand and `{ a: x }`.
    print("argument names:")
    checked = 0
    bad_args = []
    for f in list(TS_DIR.rglob("*.ts")) + list(TS_DIR.rglob("*.tsx")):
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(
            r"""invoke(?:<[^>]*>)?\(\s*["'](\w+)["']\s*,\s*\{([^}]*)\}""",
            text,
            re.S,
        ):
            cmd, body = m.group(1), m.group(2)
            # Split on commas first, then take what precedes a colon. Matching
            # `name:` alone silently skips every shorthand property, so
            # `save_note({ id, note })` reported only `note` and left `id`
            # unchecked - which is the parameter most likely to be renamed.
            names = []
            for part in body.split(","):
                part = part.strip()
                if part:
                    names.append(part.split(":")[0].strip())
            if not names:
                continue
            checked += 1
            if cmd not in rust:
                continue
            _, expected = rust[cmd]
            ok = all(to_snake(n) in expected for n in names)
            mark = "ok  " if ok else "BAD "
            print(f"  {mark}{cmd}({', '.join(names)})  <- rust expects {expected}")
            if not ok:
                bad_args.append((cmd, names, expected))

    print(f"  ({checked} call(s) with arguments)")
    print()

    # ---- CSP parity ------------------------------------------------------
    # The page carries a CSP in a meta tag and Tauri carries one in its config.
    # A browser applies every policy it is handed, so these do not override
    # each other - they intersect, and the stricter one wins. A config that
    # allows an origin the meta tag omits still blocks that origin, silently.
    print("content security policy:")
    conf_csp = extract_conf_csp()
    meta_csp = extract_meta_csp()
    if conf_csp is None and meta_csp is None:
        print("  none configured (no policy in either place)")
    else:
        conf_dirs = parse_directives(conf_csp or "")
        meta_dirs = parse_directives(meta_csp or "")
        for label, dirs in (("tauri.conf.json", conf_dirs), ("index.html", meta_dirs)):
            where = dirs.get("connect-src") or dirs.get("default-src") or []
            ok = "ipc:" in where or "http://ipc.localhost" in where
            print(f"  {label:<18} connect-src/default-src = {' '.join(where) or '(none)'}"
                  f"   IPC allowed: {'yes' if ok else 'NO'}")
            if not ok:
                problems.append(f"{label} CSP does not allow the Tauri IPC origin")

        only_conf = set(conf_dirs) - set(meta_dirs)
        only_meta = set(meta_dirs) - set(conf_dirs)
        if only_conf or only_meta:
            print(f"  drift: only in tauri.conf.json: {sorted(only_conf) or '-'}")
            print(f"  drift: only in index.html:     {sorted(only_meta) or '-'}")
            problems.append("CSP directives differ between config and meta tag")
        elif conf_dirs == meta_dirs:
            print("  the two policies are identical")
    print()

    if bad_args:
        print("argument name mismatches:")
        for cmd, sent, expected in bad_args:
            print(f"  {cmd}: js sent {sent}, rust has {expected}")
        print()
        problems += [c for c, _, _ in bad_args]

    if problems:
        print(f"\n{len(problems)} problem(s). The app would throw on these.")
        return 1

    print("Every JS invocation maps to a Rust command, with matching arguments.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())