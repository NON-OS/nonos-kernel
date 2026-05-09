#!/usr/bin/env bash
# Scan one or more directory trees for capsule SERVICE_PORT and
# REPLY_PORT u32 declarations and fail if any value repeats.
# Usage: check-capsule-ports.sh <dir> [<dir> ...]
# Exits 0 on uniqueness, 1 on collision, 2 on usage error.

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <dir> [<dir> ...]" >&2
    exit 2
fi

decls=$(grep -rnE '^\s*const (SERVICE_PORT|REPLY_PORT)\s*:\s*u32\s*=\s*[0-9]+\s*;' "$@" 2>/dev/null \
    | awk -F: '{
        loc = $1 ":" $2
        rest = $0
        sub(/^[^:]+:[0-9]+:/, "", rest)
        kind = "?"
        if (rest ~ /SERVICE_PORT/) kind = "SERVICE_PORT"
        else if (rest ~ /REPLY_PORT/) kind = "REPLY_PORT"
        value = rest
        sub(/^[^=]*=[ \t]*/, "", value)
        sub(/[ \t]*;.*/, "", value)
        print value, loc, kind
    }')

if [ -z "$decls" ]; then
    echo "check-capsule-ports: no SERVICE_PORT/REPLY_PORT declarations found under: $*" >&2
    exit 1
fi

dupes=$(echo "$decls" | awk '{print $1}' | sort -n | uniq -d)
if [ -n "$dupes" ]; then
    for v in $dupes; do
        echo "check-capsule-ports: port ${v} declared by more than one capsule:" >&2
        echo "$decls" | awk -v v="$v" '$1==v {print "  " $2 "  (" $3 ")"}' >&2
    done
    exit 1
fi

count=$(echo "$decls" | wc -l | tr -d ' ')
echo "check-capsule-ports: ${count} declarations, all unique"
exit 0
