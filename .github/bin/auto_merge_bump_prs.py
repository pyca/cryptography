"""
Approve, and enable auto-merge for, pull requests created by our automated
bump workflows.

The bump workflows sign their commits with gitsign, using the GitHub Actions
OIDC identity of the workflow run. That identity (embedded in a Fulcio
certificate, and logged to Rekor) is the workflow file on `main`, e.g.:

    https://github.com/pyca/cryptography/.github/workflows/<file>@refs/heads/main

A pull request is only approved if it consists of exactly one commit, that
commit is its head, and that commit has a valid gitsign signature from one of
the bump workflows' identities. We don't trust the PR's author, branch name,
title, etc. -- only the signature.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import typing

OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# Workflows (in .github/workflows/) whose signed commits we'll auto-merge.
BUMP_WORKFLOWS = [
    "boring-open-awslc-bump.yml",
    "downstream-version-bump.yml",
    "x509-limbo-version-bump.yml",
]

# The account that GITHUB_TOKEN reviews are attributed to.
APPROVER_LOGIN = "github-actions[bot]"

SHA_RE = re.compile(r"[0-9a-f]{40}")


def allowed_identities(repo: str) -> list[str]:
    return [
        f"https://github.com/{repo}/.github/workflows/{workflow}"
        "@refs/heads/main"
        for workflow in BUMP_WORKFLOWS
    ]


def gh(args: list[str], token: str) -> str:
    env = dict(os.environ, GH_TOKEN=token)
    return subprocess.run(
        ["gh", *args], env=env, check=True, capture_output=True, text=True
    ).stdout


def gh_api_list(path: str, token: str) -> list[typing.Any]:
    output = gh(["api", "--paginate", "--slurp", path], token)
    return [item for page in json.loads(output) for item in page]


def verify_commit(sha: str, identities: list[str]) -> typing.Optional[str]:
    """
    Returns the identity that signed `sha`, or None if it isn't validly
    signed by any of `identities`.
    """
    subprocess.run(
        ["git", "fetch", "--quiet", "--no-tags", "--depth=1", "origin", sha],
        check=True,
    )
    last_error = ""
    for identity in identities:
        result = subprocess.run(
            [
                "gitsign",
                "verify",
                f"--certificate-identity={identity}",
                f"--certificate-oidc-issuer={OIDC_ISSUER}",
                sha,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return identity
        last_error = result.stderr.strip()
    print(f"  gitsign verify failed: {last_error}")
    return None


def process_pr(
    repo: str,
    pr: dict[str, typing.Any],
    identities: list[str],
    token: str,
    merge_token: str,
    dry_run: bool,
) -> None:
    number = pr["number"]
    head_sha = pr["head"]["sha"]
    print(f"#{number}: {pr['title']} ({head_sha})")

    if pr["draft"]:
        print("  Skipping: draft")
        return
    head_repo = pr["head"]["repo"]
    if head_repo is None or head_repo["full_name"] != repo:
        print("  Skipping: not from a branch in this repository")
        return
    if not SHA_RE.fullmatch(head_sha):
        print("  Skipping: malformed head SHA")
        return

    commits = gh_api_list(f"repos/{repo}/pulls/{number}/commits", token)
    if len(commits) != 1 or commits[0]["sha"] != head_sha:
        print(f"  Skipping: has {len(commits)} commits, expected 1")
        return
    if not commits[0]["commit"]["verification"]["signature"]:
        print("  Skipping: commit is not signed")
        return

    identity = verify_commit(head_sha, identities)
    if identity is None:
        print("  Skipping: no valid signature from an allowed identity")
        return
    print(f"  Signed by {identity}")

    reviews = gh_api_list(f"repos/{repo}/pulls/{number}/reviews", token)
    already_approved = any(
        r["user"] is not None
        and r["user"]["login"] == APPROVER_LOGIN
        and r["state"] == "APPROVED"
        and r["commit_id"] == head_sha
        for r in reviews
    )
    if already_approved:
        print("  Already approved")
    elif dry_run:
        print("  Would approve (dry run)")
    else:
        gh(
            [
                "api",
                "--method=POST",
                f"repos/{repo}/pulls/{number}/reviews",
                "-f",
                f"commit_id={head_sha}",
                "-f",
                "event=APPROVE",
                "-f",
                (
                    "body=Automatically approved: this PR's only commit has "
                    f"a valid gitsign signature from `{identity}`."
                ),
            ],
            token,
        )
        print("  Approved")

    if pr["auto_merge"] is not None:
        print("  Auto-merge already enabled")
    elif dry_run:
        print("  Would enable auto-merge (dry run)")
    else:
        gh(
            [
                "pr",
                "merge",
                str(number),
                f"--repo={repo}",
                "--auto",
                "--squash",
                f"--match-head-commit={head_sha}",
            ],
            merge_token,
        )
        print("  Enabled auto-merge")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="e.g. pyca/cryptography")
    parser.add_argument("--base", default="main")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Used for reads and for approving. This must be a different identity
    # from the PR's author (GitHub doesn't let you approve your own PRs).
    token = os.environ["GH_TOKEN"]
    # Used to enable auto-merge. The merge is attributed to whoever enabled
    # auto-merge, and merges by GITHUB_TOKEN don't trigger `push` workflows,
    # so this should be a GitHub App token.
    merge_token = os.environ.get("AUTO_MERGE_TOKEN") or ""
    if not merge_token and not args.dry_run:
        print("AUTO_MERGE_TOKEN must be set", file=sys.stderr)
        return 1

    identities = allowed_identities(args.repo)
    prs = gh_api_list(
        f"repos/{args.repo}/pulls?state=open&base={args.base}&per_page=100",
        token,
    )
    failed = False
    for pr in prs:
        try:
            process_pr(
                args.repo,
                pr,
                identities,
                token=token,
                merge_token=merge_token,
                dry_run=args.dry_run,
            )
        except subprocess.CalledProcessError as e:
            failed = True
            print(f"  Error: {e}\n{e.stderr or ''}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
