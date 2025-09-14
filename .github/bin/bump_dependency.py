import argparse
import os
import re
import subprocess
import sys
from datetime import datetime


def get_remote_commit_sha(repo_url: str, branch: str) -> str:
    output = subprocess.check_output(
        ["git", "ls-remote", repo_url, f"refs/heads/{branch}"], text=True
    )
    return output.split("\t")[0]


def get_remote_latest_tag(repo_url: str, tag_pattern: str) -> str:
    output = subprocess.check_output(
        ["git", "ls-remote", "--tags", repo_url], text=True
    )
    tags = []
    for line in output.split("\n"):
        if line.strip():
            parts = line.split("\t")
            if len(parts) == 2:
                ref = parts[1]
                if ref.startswith("refs/tags/") and not ref.endswith("^{}"):
                    tag = ref.replace("refs/tags/", "")
                    if re.match(tag_pattern + "$", tag):
                        tags.append(tag)

    def version_key(tag: str) -> tuple[int, ...]:
        version = tag.lstrip("v")
        return tuple(map(int, version.split(".")))

    return sorted(tags, key=version_key)[-1]


def get_current_version_from_file(file_path: str, pattern: str) -> str:
    with open(file_path) as f:
        content = f.read()

    match = re.search(pattern, content)
    return match.group(1)


def update_file_version(
    file_path: str, old_pattern: str, new_value: str, comment_pattern: str
) -> None:
    with open(file_path) as f:
        content = f.read()

    new_content = re.sub(old_pattern, new_value, content)

    current_date = datetime.now().strftime("%b %d, %Y")
    new_content = re.sub(
        comment_pattern,
        lambda m: m.group(0).split(", as of")[0] + f", as of {current_date}.",
        new_content,
    )

    with open(file_path, "w") as f:
        f.write(new_content)


def generate_commit_message(
    repo_name: str,
    repo_url: str,
    old_version: str,
    new_version: str,
    is_tag: bool,
    commit_url_template: str,
    diff_url_template: str,
) -> str:
    if is_tag:
        version_link = (
            f"[Tag: {new_version}]({repo_url}/releases/tag/{new_version})"
        )
        diff_url = diff_url_template.format(
            repo_url=repo_url, old_version=old_version, new_version=new_version
        )
        diff_link = f"[Diff]({diff_url})"
        description = "between the previously used tag and the new tag."
    else:
        commit_url = commit_url_template.format(
            repo_url=repo_url, version=new_version
        )
        version_link = f"[Commit: {new_version}]({commit_url})"
        diff_url = diff_url_template.format(
            repo_url=repo_url, old_version=old_version, new_version=new_version
        )
        diff_link = f"[Diff]({diff_url})"
        description = (
            "between the last commit hash merged to this repository "
            "and the new commit."
        )

    return f"## {repo_name}\n{version_link}\n\n{diff_link} {description}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bump a single dependency version"
    )
    parser.add_argument(
        "--name", required=True, help="Display name for the dependency"
    )
    parser.add_argument("--repo-url", required=True, help="Git repository URL")
    parser.add_argument(
        "--branch", default="main", help="Branch to check (default: main)"
    )
    parser.add_argument(
        "--file-path", required=True, help="File containing current version"
    )
    parser.add_argument(
        "--current-version-pattern",
        required=True,
        help="Regex to extract current version (group 1)",
    )
    parser.add_argument(
        "--update-pattern", required=True, help="Regex pattern for replacement"
    )
    parser.add_argument(
        "--comment-pattern",
        required=True,
        help="Regex pattern for comment update",
    )
    parser.add_argument(
        "--tag", action="store_true", help="Check tags instead of commits"
    )
    parser.add_argument(
        "--tag-pattern", default=r"v[0-9\.]*", help="Pattern for tag matching"
    )
    parser.add_argument(
        "--commit-url-template",
        default="{repo_url}/commit/{version}",
        help="Template for commit URLs",
    )
    parser.add_argument(
        "--diff-url-template",
        default="{repo_url}/compare/{old_version}...{new_version}",
        help="Template for diff URLs",
    )

    args = parser.parse_args()

    current_version = get_current_version_from_file(
        args.file_path, args.current_version_pattern
    )

    if args.tag:
        latest_version = get_remote_latest_tag(args.repo_url, args.tag_pattern)
    else:
        latest_version = get_remote_commit_sha(args.repo_url, args.branch)

    if current_version == latest_version:
        print(f"{args.name}: No update needed (current: {current_version})")
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("HAS_UPDATES=false\n")
        return 0

    print(
        f"{args.name}: Update available "
        f"({current_version} -> {latest_version})"
    )

    replacement = args.update_pattern.replace("{new_version}", latest_version)
    update_file_version(
        args.file_path,
        args.current_version_pattern,
        replacement,
        args.comment_pattern,
    )

    commit_msg = generate_commit_message(
        args.name,
        args.repo_url,
        current_version,
        latest_version,
        args.tag,
        args.commit_url_template,
        args.diff_url_template,
    )

    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write("COMMIT_MSG<<EOF\n")
        f.write(commit_msg)
        f.write("\nEOF\n")
        f.write("HAS_UPDATES=true\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
