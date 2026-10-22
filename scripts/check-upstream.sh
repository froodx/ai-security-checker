#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
medusa_dir="$project_dir/medusa"
remote_url=$(git -C "$medusa_dir" remote get-url origin)
pinned_sha=$(git -C "$medusa_dir" rev-parse HEAD)
pinned_tag=$(git -C "$medusa_dir" describe --tags --exact-match HEAD 2>/dev/null || printf '%s' 'no exact tag')

remote_tags=$(git ls-remote --tags --refs "$remote_url" 'refs/tags/v*')
latest_tag=$(printf '%s\n' "$remote_tags" | awk -F/ 'NF {print $NF}' | sort -V | tail -1)

printf 'Pinned MEDUSA tag: %s\n' "$pinned_tag"
printf 'Pinned MEDUSA commit: %s\n' "$pinned_sha"
printf 'Latest upstream tag: %s\n' "${latest_tag:-unknown}"

if [ "$pinned_tag" = "$latest_tag" ]; then
    printf '%s\n' 'The pinned tag matches the latest upstream tag.'
elif [ -n "$latest_tag" ]; then
    printf '%s\n' 'An upstream tag differs from the current pin. No update was made.'
fi

if git -C "$medusa_dir" verify-tag "$pinned_tag" >/dev/null 2>&1; then
    printf '%s\n' 'The pinned tag has a locally verifiable cryptographic signature.'
else
    printf '%s\n' 'The pinned tag has no locally verifiable cryptographic signature.'
fi
