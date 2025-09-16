#!/bin/bash

# Extract downstream info from ci.yml using yq
DOWNSTREAMS=$(yq '.jobs.linux-downstream.strategy.matrix.include[] | .DOWNSTREAM + ":" + .REPO + ":" + .REF' .github/workflows/ci.yml)
echo "Found downstreams:"
echo "$DOWNSTREAMS"

# Create individual bump steps for each downstream
HAS_ANY_UPDATES=false
COMBINED_COMMIT_MSG=""

while IFS=: read -r downstream repo ref; do
    echo "Processing $downstream..."

    # Convert repo to GitHub URL
    repo_url="https://github.com/$repo"

    # Extract branch name and determine if it's a tag from the comment in ci.yml
    # Find the comment line for this downstream by looking for the REF line and getting the comment above it
    comment_line=$(grep -B1 "REF: $ref" .github/workflows/ci.yml | grep "^[[:space:]]*#" | tail -1)

    # Parse the comment to determine branch and whether it's a tag
    if echo "$comment_line" | grep -q "release tag"; then
        # This is a tag-based entry
        tag_args="--tag"
        branch=""  # Not used for tags
        comment_pattern="# Latest release tag of $downstream, as of.*\\."
    else
        # This is a branch-based entry, extract branch name
        branch=$(echo "$comment_line" | sed -n 's/.*on the .* \([^ ]*\) branch.*/\1/p')
        tag_args=""
        comment_pattern="# Latest commit on the $downstream .* branch, as of.*\\."
    fi

    echo "Using branch: $branch, tag_args: $tag_args"

    # Create pattern to match REF in ci.yml
    ref_pattern="REF: ($ref)"
    replacement_pattern="REF: {new_version}"

    # Run bump_dependency.py
    python3 .github/bin/bump_dependency.py \
        --name "$downstream" \
        --repo-url "$repo_url" \
        --branch "$branch" \
        --file-path ".github/workflows/ci.yml" \
        --current-version-pattern "$ref_pattern" \
        --update-pattern "$replacement_pattern" \
        --comment-pattern "$comment_pattern" \
        $tag_args

    # Check if this downstream had updates
    if [ -f "$GITHUB_OUTPUT" ]; then
        if grep -q "HAS_UPDATES=true" "$GITHUB_OUTPUT"; then
            HAS_ANY_UPDATES=true
            # Extract commit message for this downstream
            DOWNSTREAM_MSG=$(sed -n '/COMMIT_MSG<<EOF/,/^EOF$/p' "$GITHUB_OUTPUT" | sed '1d;$d')
            if [ -n "$COMBINED_COMMIT_MSG" ]; then
                COMBINED_COMMIT_MSG="$COMBINED_COMMIT_MSG"$'\n\n'"$DOWNSTREAM_MSG"
            else
                COMBINED_COMMIT_MSG="$DOWNSTREAM_MSG"
            fi
        fi
    fi
done <<< "$DOWNSTREAMS"

# Set final outputs
echo "HAS_UPDATES=$HAS_ANY_UPDATES" >> "$GITHUB_OUTPUT"
if [ "$HAS_ANY_UPDATES" = "true" ]; then
    echo "COMMIT_MSG<<EOF" >> "$GITHUB_OUTPUT"
    echo "$COMBINED_COMMIT_MSG" >> "$GITHUB_OUTPUT"
    echo "EOF" >> "$GITHUB_OUTPUT"
fi
