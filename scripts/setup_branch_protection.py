"""Create the main-branch ruleset via the GitHub API.

Written in Python rather than PowerShell because two of the required check
contexts contain an em dash, and every PowerShell quoting path available here
either mangled it or failed outright.
"""

import json
import subprocess
import sys

REPO = "SudhirDevOps1/vaultnote"
ADMIN_ID = 234449571

# Must match the `name:` fields on the jobs in .github/workflows/ci.yml
# exactly. The em dash is written as an escape rather than a literal: a literal
# has been silently mangled once already by the toolchain writing this file,
# and a mismatched context is the dangerous failure - it never reports as
# required, so the branch looks protected while it is not.
EM = "—"
CHECKS = [
    f"Frontend {EM} typecheck + build",
    f"Rust {EM} check, test, clippy",
    "Secret scan",
]


def gh(*args, data=None, method="GET"):
    cmd = ["gh", "api", *args]
    if method != "GET":
        cmd = ["gh", "api", "-X", method, *args]
    if data is not None:
        cmd += ["--input", "-"]
    r = subprocess.run(
        cmd,
        input=json.dumps(data) if data is not None else None,
        capture_output=True,
        # GitHub returns UTF-8. `text=True` alone decodes using the Windows
        # locale codepage, which turns an em dash into mojibake and makes the
        # required-check comparison fail for a reason that has nothing to do
        # with the strings being wrong.
        encoding="utf-8",
    )
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def main():
    # Confirm the context strings exist in the repo before creating a gate on
    # them. Creating a ruleset with a typo in a context is worse than none:
    # it looks like protection and is not.
    code, out, _ = gh(f"repos/{REPO}/actions/runs/39163029361/jobs")
    if code != 0:
        print("could not read job names", file=sys.stderr)
        return 1
    actual = {j["name"] for j in json.loads(out)["jobs"]}
    missing = [c for c in CHECKS if c not in actual]
    if missing:
        print("ABORT: these contexts do not exist on a real run:")
        for m in missing:
            print(f"  {m!r}")
        print("actual job names:", sorted(actual), file=sys.stderr)
        return 1

    ruleset = {
        "name": "main",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": c} for c in CHECKS],
                    "strict_required_status_checks_policy": True,
                },
            },
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
        ],
        # No bypass actor on purpose. main is only reachable through a pull
        # request whose three checks have passed. Adding an admin bypass would
        # make the banner disappear while removing the guarantee, which is the
        # failure mode this whole setup exists to prevent.
        "bypass_actors": [],
    }

    code, out, err = gh("repos/{}/rulesets".format(REPO), data=ruleset, method="POST")
    if code != 0:
        print("create failed:", err, file=sys.stderr)
        return 1

    created = json.loads(out)
    print("ruleset id:", created.get("id"))
    print("name      :", created.get("name"))
    print("enforcement:", created.get("enforcement"))

    code, out, _ = gh(f"repos/{REPO}/rulesets/{created['id']}")
    detail = json.loads(out)
    for rule in detail.get("rules", []):
        if rule["type"] == "required_status_checks":
            ctxs = [
                c["context"] for c in rule["parameters"]["required_status_checks"]
            ]
            print("required checks:", ctxs)
    print("rules      :", [r["type"] for r in detail.get("rules", [])])
    print("bypass     :", detail.get("bypass_actors"))
    return 0


if __name__ == "__main__":
    sys.exit(main())