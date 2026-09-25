#!/usr/bin/env python3
"""Scan every template with the semgrep community rules.

Databricks Apps runs semgrep with the community rules against deployed app
source, so each template must scan cleanly. This script reproduces that scan
and fails if any template has a finding that is security-category or
ERROR-severity.

It runs in CI (.github/workflows/semgrep.yml) and locally:

    git clone https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules
    git -C /tmp/semgrep-rules checkout <SEMGREP_RULES_REF from semgrep.yml>
    pip install semgrep==<SEMGREP_VERSION from semgrep.yml>
    python .scripts/semgrep-scan.py --rules /tmp/semgrep-rules [TEMPLATE_DIR ...]

With no template directories given, every top-level template directory is
scanned. Semgrep only scans git-tracked files. Its default ignore list (which
skips test directories) is disabled, because those files are deployed too.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.resolve()

# Directories in the semgrep-rules repo that hold tooling, not rules
NON_RULE_DIRS = {".github", "scripts", "stats"}


def collect_rules(rules_repo: Path, dest: Path) -> int:
    """Copy rule files (not tests or fixtures) from the semgrep-rules repo into dest."""
    count = 0
    for path in rules_repo.rglob("*"):
        rel = path.relative_to(rules_repo)
        if not path.is_file() or path.suffix not in (".yaml", ".yml"):
            continue
        if rel.parts[0] in NON_RULE_DIRS or rel.parts[0].startswith("."):
            continue
        if ".test." in path.name or ".fixed." in path.name or rel.name == "template.yaml":
            continue
        if not path.read_text(errors="ignore").startswith(("rules:", "---\nrules:")):
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        count += 1
    return count


def template_dirs() -> list[str]:
    return sorted(
        p.name for p in REPO_ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")
    )


def is_blocking(result: dict) -> bool:
    extra = result["extra"]
    return extra["metadata"].get("category") == "security" or extra["severity"] == "ERROR"


def run_semgrep(config_dir: Path, targets: list[str], output: Path, jobs: int) -> None:
    ignore_file = REPO_ROOT / ".semgrepignore"
    created_ignore = not ignore_file.exists()
    if created_ignore:
        # An empty .semgrepignore replaces semgrep's default ignore list
        ignore_file.write_text("")
    try:
        cmd = [
            "semgrep", "scan",
            "--config", str(config_dir),
            "--metrics", "off",
            "--json", "--output", str(output),
            "--jobs", str(jobs),
            *targets,
        ]
        # Argument list built from script inputs (no shell)
        subprocess.run(cmd, cwd=REPO_ROOT, check=False)  # nosemgrep: dangerous-subprocess-use-audit
    finally:
        if created_ignore:
            ignore_file.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules", required=True, type=Path, help="Path to a semgrep-rules checkout")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("templates", nargs="*", help="Template directories (default: all)")
    args = parser.parse_args()

    targets = args.templates or template_dirs()
    in_ci = os.getenv("GITHUB_ACTIONS") == "true"

    with tempfile.TemporaryDirectory() as tmp:
        config_dir = Path(tmp) / "rules"
        print(f"Loaded {collect_rules(args.rules.resolve(), config_dir)} rule files")
        output = Path(tmp) / "results.json"
        run_semgrep(config_dir, targets, output, args.jobs)
        if not output.exists():
            print("semgrep produced no output", file=sys.stderr)
            return 2
        data = json.loads(output.read_text())

    findings = [r for r in data["results"] if is_blocking(r)]
    for r in findings:
        rule = r["check_id"].split(".")[-1]
        severity = r["extra"]["severity"]
        message = " ".join(r["extra"]["message"].split())
        if in_ci:
            print(f"::error file={r['path']},line={r['start']['line']},title=semgrep {rule}::{message}")
        else:
            print(f"{r['path']}:{r['start']['line']}  {rule}  [{severity}]  {message[:160]}")

    print(f"\n{len(findings)} blocking finding(s) in {len(targets)} template(s)")
    if data.get("errors"):
        print(f"({len(data['errors'])} semgrep error(s), e.g. unparsable files; not blocking)")
    if findings:
        print(
            "Fix each finding, or for a verified false positive add an inline "
            "`nosemgrep: <rule-id>` comment with a short justification."
        )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
