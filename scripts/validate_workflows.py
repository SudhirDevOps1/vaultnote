"""Parse every workflow in .github/workflows and fail on anything malformed.

A workflow with a syntax error does not fail loudly at review time. GitHub
records it as a zero-second failed run against the commit, the kind that gets
scrolled past, and the only symptom is that releases silently stop working.

That is exactly how release.yml shipped broken: a PowerShell here-string
inside a YAML block scalar. Nothing in the test suite covered it, because the
test suite only ever ran the workflows that parsed.

Run with:  python scripts/validate_workflows.py
"""

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent
WF_DIR = ROOT / ".github" / "workflows"


def main() -> int:
    if not WF_DIR.is_dir():
        print(f"no workflow directory at {WF_DIR}")
        return 0

    files = sorted(WF_DIR.glob("*.yml")) + sorted(WF_DIR.glob("*.yaml"))
    if not files:
        print("no workflows found")
        return 0

    failures = []

    for path in files:
        rel = path.relative_to(ROOT)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            failures.append((rel, f"not valid UTF-8: {e}"))
            continue

        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            failures.append((rel, f"YAML error: {e}"))
            continue

        if not isinstance(doc, dict):
            failures.append((rel, "top level is not a mapping"))
            continue

        # `on:` is parsed as the boolean True by YAML 1.1, so check both.
        trig = doc.get("on", doc.get(True))
        if trig is None:
            failures.append((rel, "no trigger: `on:` is missing"))
            continue

        jobs = doc.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            failures.append((rel, "no jobs defined"))
            continue

        for name, job in jobs.items():
            if not isinstance(job, dict):
                failures.append((rel, f"job {name!r} is not a mapping"))
                continue
            if "runs-on" not in job and "uses" not in job:
                failures.append((rel, f"job {name!r} has neither runs-on nor uses"))
            if "steps" in job and not isinstance(job["steps"], list):
                failures.append((rel, f"job {name!r} steps is not a list"))

        if not failures or all(f[0] != rel for f in failures):
            print(f"OK    {rel}  ({len(jobs)} job(s))")

    if failures:
        print()
        for rel, why in failures:
            print(f"FAIL  {rel}: {why}")
        print(f"\n{len(failures)} workflow problem(s).")
        return 1

    print(f"\nAll {len(files)} workflow(s) parse.")
    return 0


if __name__ == "__main__":
    sys.exit(main())