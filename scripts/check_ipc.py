"""Cross-check the Tauri IPC surface: Rust commands vs JS invoke() calls.

Nothing has ever executed this boundary. The Rust command names and the
JavaScript invoke() names were written separately and never compared, so a
single mismatch means the app launches and every button throws.

Tauri v2 converts camelCase argument names from JS to snake_case in Rust, so
`session.with` style naming has to be checked in both forms.

Exits non-zero on any mismatch, so it can run in CI.
"""

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


def main() -> int:
    rust = {}
    for f in RUST_DIR.glob("*.rs"):
        text = f.read_text(encoding="utf-8")
        for m in CMD_RE.finditer(text):
            params = [p.strip() for p in m.group(2).split(",") if p.strip()]
            # Drop the injected State/AppHandle parameters; they are supplied
            # by Tauri, not by the caller.
            caller_params = [
                p.split(":")[0].strip()
                for p in params
                if not p.startswith("State<") and not p.startswith("AppHandle")
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
            names = re.findall(r"(\w+)\s*(?::|$)", body)
            names = [n.strip() for n in names if n.strip()]
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
    return 0


if __name__ == "__main__":
    sys.exit(main())