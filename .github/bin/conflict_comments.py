# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""Comments on every open pull request that conflicts with its base branch,
once per push to it: what `.github/workflows/conflicts.yml` runs after each
merge to main.

Each comment carries a hidden marker naming the pull request's head commit.
A pull request that already has this token's comment for its current head is
skipped, so a pull request is told once that it conflicts, and again only
after a new push that still conflicts.
"""

import argparse
import json
import os
import time
import urllib.request

API = "https://api.github.com"
MARKER = "<!-- conflict-check: {head} -->"

# `comments(last: 100)`: a marker older than a pull request's last 100
# comments is missed, and the comment posted again.
QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: 50, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        isInMergeQueue
        mergeable
        headRefOid
        baseRefName
        comments(last: 100) { nodes { viewerDidAuthor body } }
      }
    }
  }
}
"""

BODY = """{marker}
This pull request has conflicts with `{base}`, found after {sha} landed on \
`main`. Please rebase, or merge `{base}`, to resolve them.

<sub>Posted by `.github/workflows/conflicts.yml`, once per push to a \
conflicting pull request.</sub>
"""


class Api:
    def __init__(self, token):
        self.token = token

    def request(self, method, path, payload):
        req = urllib.request.Request(
            API + path,
            data=json.dumps(payload).encode(),
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)

    def graphql(self, query, variables):
        out = self.request(
            "POST", "/graphql", {"query": query, "variables": variables}
        )
        if out.get("errors"):
            raise RuntimeError(f"GraphQL errors: {out['errors']}")
        return out["data"]

    def comment(self, repo, number, body):
        self.request(
            "POST", f"/repos/{repo}/issues/{number}/comments", {"body": body}
        )


def open_pulls(api, repo):
    """Every open pull request, as the GraphQL query's nodes."""
    owner, name = repo.split("/")
    pulls, after = [], None
    while True:
        page = api.graphql(
            QUERY, {"owner": owner, "name": name, "after": after}
        )
        prs = page["repository"]["pullRequests"]
        pulls += prs["nodes"]
        if not prs["pageInfo"]["hasNextPage"]:
            return pulls
        after = prs["pageInfo"]["endCursor"]


def resolve(api, repo, attempts, delay):
    """The open pull requests whose mergeability GitHub knows, by number,
    asking again for those it does not yet; and the numbers still unknown."""
    known, queued, unknown = {}, set(), set()
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            time.sleep(delay)
        unknown = set()
        for pr in open_pulls(api, repo):
            number = pr["number"]
            if pr["isInMergeQueue"]:
                if number not in queued:
                    print(f"#{number}: in the merge queue: skipped")
                queued.add(number)
            elif pr["mergeable"] != "UNKNOWN":
                if number not in known:
                    state = pr["mergeable"].lower()
                    print(f"#{number}: {state} at {pr['headRefOid']}")
                known[number] = pr
            elif number not in known:
                unknown.add(number)
        if not unknown:
            break
        waiting = ", ".join(f"#{n}" for n in sorted(unknown))
        print(f"attempt {attempt}/{attempts}: still unknown: {waiting}")
    return known, sorted(unknown)


def needs_comment(pr):
    """Whether `pr` conflicts and has no comment of ours for its head."""
    if pr["mergeable"] != "CONFLICTING":
        return False
    marker = MARKER.format(head=pr["headRefOid"])
    return not any(
        c["viewerDidAuthor"] and marker in c["body"]
        for c in pr["comments"]["nodes"]
    )


def body(pr, sha):
    return BODY.format(
        marker=MARKER.format(head=pr["headRefOid"]),
        base=pr["baseRefName"],
        sha=sha,
    )


def run(api, repo, sha, attempts, delay, dry_run):
    known, unknown = resolve(api, repo, attempts, delay)
    for number, pr in sorted(known.items()):
        if needs_comment(pr):
            print(f"#{number}: newly conflicting: commenting")
            if not dry_run:
                api.comment(repo, number, body(pr, sha))
        elif pr["mergeable"] == "CONFLICTING":
            print(f"#{number}: already told about this head")
    for number in unknown:
        print(f"#{number}: mergeability still unknown: skipped")
    print(f"{len(known)} checked, {len(unknown)} unknown")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repo", help="OWNER/REPO")
    parser.add_argument("sha", help="the commit of main that was just pushed")
    parser.add_argument("--attempts", type=int, default=24)
    parser.add_argument("--delay", type=float, default=5)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what it would comment on",
    )
    args = parser.parse_args()
    api = Api(os.environ["GITHUB_TOKEN"])
    run(api, args.repo, args.sha, args.attempts, args.delay, args.dry_run)


if __name__ == "__main__":
    main()
