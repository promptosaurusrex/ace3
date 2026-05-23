#!/usr/bin/env python3
#
# prepare a release for a milestone:
#   - checks out a new r/X.Y.Z branch off main
#   - bumps ACE_VERSION in the Dockerfile
#   - prepends a new CHANGELOG section linking the milestone's merged PRs
#   - commits, pushes, and opens a release PR back to main
#
# assumes the gh CLI is installed and authenticated.
#

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date

ACE_DIR = "/opt/ace"
DOCKERFILE = os.path.join(ACE_DIR, "Dockerfile")
CHANGELOG = os.path.join(ACE_DIR, "CHANGELOG.md")
MILESTONE_RE = re.compile(r"^\d+\.\d+\.\d+$")


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run(cmd, capture=False):
    try:
        return subprocess.run(cmd, check=True, text=True, capture_output=capture)
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() if capture and exc.stderr else ""
        suffix = f": {details}" if details else ""
        fail(f"command failed ({' '.join(cmd)}){suffix}")


def validate_milestone_format(milestone):
    if not MILESTONE_RE.match(milestone):
        fail(f"milestone must be in X.Y.Z format, got {milestone!r}")


def validate_cwd():
    cwd = os.getcwd()
    if cwd != ACE_DIR:
        fail(f"must be run from {ACE_DIR}, cwd is {cwd}")


def validate_branch():
    result = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture=True)
    branch = result.stdout.strip()
    if branch != "main":
        fail(f"current branch must be main, got {branch!r}")


def validate_milestone_exists(milestone):
    result = run(
        [
            "gh", "api", "--paginate",
            "repos/{owner}/{repo}/milestones?state=all&per_page=100",
            "--jq", ".[].title",
        ],
        capture=True,
    )
    titles = result.stdout.splitlines()
    if milestone not in titles:
        fail(f"milestone {milestone!r} not found on GitHub")


def create_branch(milestone):
    run(["git", "checkout", "-b", f"r/{milestone}"])


def update_dockerfile(milestone):
    with open(DOCKERFILE) as fp:
        content = fp.read()
    new_content, count = re.subn(
        r"^ARG ACE_VERSION=.*$",
        f"ARG ACE_VERSION={milestone}",
        content,
        flags=re.MULTILINE,
    )
    if count != 1:
        fail(f"expected exactly 1 ARG ACE_VERSION line in {DOCKERFILE}, found {count}")
    with open(DOCKERFILE, "w") as fp:
        fp.write(new_content)


def fetch_prs(milestone):
    result = run(
        [
            "gh", "pr", "list",
            "--search", f"milestone:{milestone} is:merged base:main",
            "--json", "number,title,url",
            "--limit", "200",
        ],
        capture=True,
    )
    prs = json.loads(result.stdout)
    if not prs:
        fail(f"no merged PRs found for milestone {milestone!r}")
    prs.sort(key=lambda p: p["number"])
    return prs


def update_changelog(milestone, prs):
    with open(CHANGELOG) as fp:
        content = fp.read()

    heading_marker = f"## [{milestone}]"
    if heading_marker in content:
        fail(f"CHANGELOG already has a {heading_marker} section")

    bullets = "\n".join(f"- [{p['title']}]({p['url']})" for p in prs)
    new_section = f"## [{milestone}] - {date.today().isoformat()}\n\n{bullets}\n\n"

    match = re.search(r"^## \[", content, flags=re.MULTILINE)
    if not match:
        fail(f"no existing '## [' heading found in {CHANGELOG}")

    insert_at = match.start()
    new_content = content[:insert_at] + new_section + content[insert_at:]
    with open(CHANGELOG, "w") as fp:
        fp.write(new_content)
    return bullets


def commit(milestone):
    run(["git", "add", "Dockerfile", "CHANGELOG.md"])
    run(["git", "commit", "-m", f"v{milestone}"])


def push_branch(milestone):
    run(["git", "push", "-u", "origin", f"r/{milestone}"])


def create_pr(milestone, body):
    run(
        [
            "gh", "pr", "create",
            "--base", "main",
            "--head", f"r/{milestone}",
            "--title", f"v{milestone}",
            "--body", body,
            "--label", "release",
            "--milestone", milestone,
        ],
    )


def main():
    parser = argparse.ArgumentParser(
        description="prepare a release branch and PR for a milestone"
    )
    parser.add_argument("--milestone", required=True, help="release milestone in X.Y.Z format")
    args = parser.parse_args()

    validate_milestone_format(args.milestone)
    validate_cwd()
    validate_branch()
    validate_milestone_exists(args.milestone)

    create_branch(args.milestone)
    update_dockerfile(args.milestone)
    prs = fetch_prs(args.milestone)
    body = update_changelog(args.milestone, prs)
    commit(args.milestone)
    push_branch(args.milestone)
    create_pr(args.milestone, body)

    print(f"release PR opened for v{args.milestone}")


if __name__ == "__main__":
    main()
