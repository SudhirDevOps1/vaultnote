"""Add an admin bypass to the main ruleset so release-please's own PR can merge.

release-please creates its release PR using GITHUB_TOKEN, and GitHub does not
run workflows for events created with that token. So the release PR never gets
status checks, and a ruleset that requires status checks will not let it merge.
No tag, no release, no installers - the loop stops silently every time.

Scoped to the admin role rather than to a branch-name pattern. Excluding
`release-please--*` from the ruleset would also let anyone who can push create
a branch with that name and merge it unchecked. A bypass requires a human with
admin rights to make a deliberate choice.

Idempotent: re-running leaves an identical ruleset.
"""

import json
import subprocess
import sys

REPO = "SudhirDevOps1/vaultnote"
RULESET = "25357756"
BYPASS = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]


def gh(*args):
    r = subprocess.run(
        ["gh", "api", *args], capture_output=True, text=True, encoding="utf-8"
    )
    if r.returncode != 0:
        print(r.stderr.strip(), file=sys.stderr)
        raise SystemExit(1)
    return json.loads(r.stdout)


def main():
    current = gh(f"repos/{REPO}/rulesets/{RULESET}")

    if current.get("bypass_actors") == BYPASS:
        print("bypass already present - nothing to do")
        return 0

    payload = {
        "name": current["name"],
        "target": current["target"],
        "enforcement": current["enforcement"],
        "conditions": current["conditions"],
        "rules": current["rules"],
        "bypass_actors": BYPASS,
    }

    out = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "PUT",
            f"repos/{REPO}/rulesets/{RULESET}",
            "--input",
            "-",
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if out.returncode != 0:
        print(out.stderr.strip(), file=sys.stderr)
        return 1

    final = gh(f"repos/{REPO}/rulesets/{RULESET}")
    print("enforcement  :", final["enforcement"])
    print("bypass_actors:", json.dumps(final.get("bypass_actors")))
    print("rules        :", ", ".join(r["type"] for r in final["rules"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())