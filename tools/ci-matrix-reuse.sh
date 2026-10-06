#!/usr/bin/env bash
# Reuse ONLY a successful full PR matrix for an identical two-parent merge
# tree. An API error, expired proof, failure or pending run means rebuild.
# No release candidate or exact-commit validation is reused by this helper.
# tools/ci-matrix-reuse.sh BASE HEAD
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")/.."
base=${1:-} head=${2:-HEAD}
rebuild() { printf 'options=build\nreuse_run=\n'; exit 0; }
command -v gh >/dev/null 2>&1 || rebuild
command -v jq >/dev/null 2>&1 || rebuild
parents=$(git show -s --format=%P "$head") || rebuild
read -r first source extra <<< "$parents" || rebuild
[ -n "$source" ] && [ -z "${extra:-}" ] && [ "$first" = "$base" ] || rebuild
tree=$(git rev-parse "$head^{tree}") || rebuild
[ "$tree" = "$(git rev-parse "$source^{tree}")" ] || rebuild
runs=$(gh run list --workflow CI --commit "$source" --limit 20 \
    --json databaseId,headSha,status,conclusion,event 2>/dev/null) || rebuild
# Do not step over a newer failed/pending run to reach an older green one.
run=$(printf '%s' "$runs" | jq -ce --arg sha "$source" \
    '[.[] | select(.headSha == $sha and .event == "pull_request")][0]' 2>/dev/null) || rebuild
[ "$(printf '%s' "$run" | jq -r '.status + ":" + .conclusion')" = completed:success ] || rebuild
id=$(printf '%s' "$run" | jq -r .databaseId)
case "$id" in ''|*[!0-9]*) rebuild ;; esac
artifacts=$(gh api "repos/{owner}/{repo}/actions/runs/$id/artifacts" 2>/dev/null) || rebuild
printf '%s' "$artifacts" | jq -e --arg name "ci-options-tree-$tree" \
    'any(.artifacts[]; .name == $name and .expired == false)' >/dev/null 2>&1 || rebuild
printf 'options=reused\nreuse_run=%s\n' "$id"
