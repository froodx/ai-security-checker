#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
medusa_dir="$project_dir/medusa"
venv_python="$project_dir/.venv/bin/python"
venv_medusa="$project_dir/.venv/bin/medusa"
approved=false
allow_unsigned=false
tag=''

usage() {
    printf '%s\n' 'Usage: scripts/update-upstream.sh --tag vYYYY.N.N --approve [--allow-unsigned]'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tag)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            tag=$2
            shift 2
            ;;
        --approve)
            approved=true
            shift
            ;;
        --allow-unsigned)
            allow_unsigned=true
            shift
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

[ "$approved" = true ] || { printf '%s\n' 'Refusing update without --approve.' >&2; exit 2; }
printf '%s' "$tag" | grep -Eq '^v[0-9][0-9A-Za-z._-]*$' || {
    printf '%s\n' 'The requested tag name is invalid.' >&2
    exit 2
}
[ -x "$venv_python" ] && [ -x "$venv_medusa" ] || {
    printf '%s\n' 'Install the project virtual environment before updating MEDUSA.' >&2
    exit 2
}
git -C "$medusa_dir" diff --quiet && git -C "$medusa_dir" diff --cached --quiet || {
    printf '%s\n' 'The MEDUSA submodule contains local changes. Update refused.' >&2
    exit 2
}

previous_sha=$(git -C "$medusa_dir" rev-parse HEAD)
remote_url=$(git -C "$medusa_dir" remote get-url origin)
remote_ref=$(git ls-remote --tags "$remote_url" "refs/tags/$tag" "refs/tags/$tag^{}")
[ -n "$remote_ref" ] || { printf 'Upstream tag not found: %s\n' "$tag" >&2; exit 2; }

git -C "$medusa_dir" fetch --force origin "refs/tags/$tag:refs/tags/$tag"
if ! git -C "$medusa_dir" verify-tag "$tag" >/dev/null 2>&1; then
    if [ "$allow_unsigned" != true ]; then
        printf '%s\n' 'The tag has no locally verifiable signature. Re-run with --allow-unsigned only after reviewing the tag and commit.' >&2
        exit 2
    fi
    printf '%s\n' 'Warning: continuing with an unsigned or locally unverifiable tag after explicit approval.'
fi

mkdir -p "$project_dir/.state"
chmod 700 "$project_dir/.state"
printf '%s\n' "$previous_sha" > "$project_dir/.state/previous-medusa-sha"
chmod 600 "$project_dir/.state/previous-medusa-sha"

rollback() {
    printf 'Smoke test failed. Returning MEDUSA to %s.\n' "$previous_sha" >&2
    git -C "$medusa_dir" checkout --detach "$previous_sha"
    "$venv_python" -m pip install --no-deps --force-reinstall "$medusa_dir" >/dev/null
}

git -C "$medusa_dir" checkout --detach "$tag"
if ! "$venv_python" -m pip install --no-deps --force-reinstall "$medusa_dir" >/dev/null \
    || ! "$venv_medusa" --version \
    || ! "$venv_medusa" scan --help >/dev/null \
    || ! "$venv_python" -m pytest -q "$project_dir/tests/test_medusa_adapter.py"; then
    rollback
    exit 1
fi

new_sha=$(git -C "$medusa_dir" rev-parse HEAD)
printf 'MEDUSA now points to %s at %s.\n' "$tag" "$new_sha"
printf '%s\n' 'Review the submodule diff and full test suite before committing.'
printf 'Rollback command: git -C %s checkout --detach %s\n' "$medusa_dir" "$previous_sha"
