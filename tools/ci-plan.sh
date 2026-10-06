#!/usr/bin/env bash
# Classify a Git range for CI.  A documentation-only change still gets its
# own gates, but it cannot affect a compiled image and must not consume the
# cross-build matrix.
# Shipping-only tool/UI/host-test edits keep every non-matrix gate. Shared
# headers, stack/library/driver/vendor/build/CI changes and unknown paths keep
# the full matrix. Manual dispatch and the weekly schedule always force full.
#
#   tools/ci-plan.sh BASE HEAD [EVENT]
#
# Output is suitable for appending to $GITHUB_OUTPUT.
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

base="${1:-}"
head="${2:-HEAD}"
zero=0000000000000000000000000000000000000000
event="${3:-}"

mode=full
reason=unbounded_range
files=()

if [ "$event" = workflow_dispatch ] || [ "$event" = schedule ]; then
    reason=forced_full
elif [ -n "$base" ] && [ "$base" != "$zero" ] &&
   git cat-file -e "$base^{commit}" 2>/dev/null &&
   git cat-file -e "$head^{commit}" 2>/dev/null; then
    # Resolve the diff successfully before reading it. A failed producer in
    # process substitution must not look like an empty documentation change.
    git diff --no-renames --name-only "$base" "$head" >/dev/null
    while IFS= read -r -d '' path; do files+=("$path"); done \
        < <(git diff --no-renames --name-only -z "$base" "$head")

    if [ "${#files[@]}" -eq 0 ]; then
        mode=docs
        reason=no_changed_files
    else
        mode=docs
        reason=documentation_only
        for path in "${files[@]}"; do
            case "$path" in
                *.h|*.cmake|*/CMakeLists.txt|*/Makefile)
                    mode=full; reason=shared_build_input; break ;;
                # These are generated inputs/outputs, not prose merely because
                # they live under docs/.  The survey gates must see them.
                docs/aminet-survey/*.tsv|src/tools/*.c|tests/*/host/*.c|src/tools/web/*.ts|src/tools/web/*.css|src/tools/web/*.html)
                    # These affect shipping tools, host tests or the web UI,
                    # not the optional stack/library layouts. All non-matrix
                    # gates still run, including release preset builds.
                    mode=shipping; reason=shipping_inputs ;;
                *.md|*.guide|*.info|docs/*|tests/HARNESSES|LICENSE) ;;
                *) mode=full; reason=build_input; break ;;
            esac
        done
    fi
fi

printf 'mode=%s\n' "$mode"
printf 'reason=%s\n' "$reason"
printf 'changed=%s\n' "${#files[@]}"
