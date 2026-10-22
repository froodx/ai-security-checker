#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
state_dir="$project_dir/.state"
mkdir -p "$state_dir"
chmod 700 "$state_dir"

if command -v flock >/dev/null 2>&1; then
    nohup flock -n "$state_dir/startup-scan.lock" \
        timeout 15m "$project_dir/ai-security-check" scan --target hermes --mode basic \
        >"$state_dir/startup-scan.out" 2>&1 </dev/null &
else
    nohup timeout 15m "$project_dir/ai-security-check" scan --target hermes --mode basic \
        >"$state_dir/startup-scan.out" 2>&1 </dev/null &
fi
printf 'Started a bounded background Basic scan with process ID %s.\n' "$!"
