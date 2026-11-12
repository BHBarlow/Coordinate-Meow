#!/usr/bin/env bash
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# find-beacons.sh - given ONE known-bad binary (e.g. a Realm / SpellShift
# "imix" beacon), find the rest across the system. Read-only.
#
# Three pivots from the one you found:
#   1. exact SHA256   - identical copies (also works across hosts via coordinate)
#   2. same size      - catches per-host rebuilds whose hash changed
#   3. drop-time      - every file modified within N minutes of the beacon
#
# Also hashes every running process's /proc/<pid>/exe, so a beacon that has been
# deleted from disk but is still running is still caught.
#
# coordinate cannot pass arguments, so give the path in an env var:
#   coordinate ... -E BEACON=/usr/local/bin/imix
#
# Settings (env vars):
#   BEACON            path to the known binary (locally you may pass it as $1)
#   BEACON_MTIME_MIN  also list files modified within this many minutes of the
#                     beacon's mtime (default 0 = off)
#   BEACON_MAX        max lines per section (default 500, 0 = no limit)

set -u

TARGET_INPUT=${BEACON:-${1:-}}
if [[ -z "$TARGET_INPUT" ]]; then
    echo "Usage: $0 /full/path/to/binary   (or -E BEACON=/path under coordinate)" >&2
    exit 1
fi

TARGET="$(readlink -f "$TARGET_INPUT" 2>/dev/null || echo "$TARGET_INPUT")"
if [[ ! -f "$TARGET" ]]; then
    echo "[!] File not found: $TARGET_INPUT" >&2
    exit 1
fi

[[ ${EUID:-$(id -u)} -ne 0 ]] && echo "[!] Not root - some locations will be unreadable." >&2

MAX=${BEACON_MAX:-500}
case $MAX in ''|*[!0-9]*) MAX=500 ;; esac
cap() {
    if [[ "$MAX" -eq 0 ]]; then cat
    else awk -v m="$MAX" 'NR<=m; NR==m+1{print "    ... capped at "m" lines (BEACON_MAX=0 for all)"}'
    fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/beacon.XXXXXX") || { echo "mktemp failed" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' INT TERM

HASH=$(sha256sum "$TARGET" | awk '{print $1}')
SIZE=$(stat -c %s "$TARGET")
MTIME=$(stat -c %Y "$TARGET")

echo "[*] Target : $TARGET"
echo "[*] SHA256 : $HASH"
echo "[*] Size   : $SIZE bytes"
echo "[*] Mtime  : $(stat -c %y "$TARGET")"
echo

# --- build prune list: /proc /sys, container stores, and network mounts ------
PRUNE=( -path /proc -o -path /sys -o -path /snap -o -path /var/lib/snapd/snap \
        -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/lxcfs )
if [[ -r /proc/mounts ]]; then
    while read -r _dev mp fs _rest; do
        case $fs in
            nfs|nfs4|cifs|smb3|smbfs|fuse.sshfs|9p|ceph|glusterfs|fuse.s3fs|fuse.rclone|autofs)
                PRUNE+=( -o -path "$mp" ) ;;
        esac
    done < /proc/mounts
fi

# --- one walk: hash every same-size file (same size is the only cheap prefilter)
echo "[*] Searching filesystem by size, then hashing matches..."
find / \( "${PRUNE[@]}" \) -prune -o -type f -size "${SIZE}c" -print0 2>/dev/null \
    | xargs -0 -r sha256sum 2>/dev/null > "$WORK/samesize"

strip_hash() { sed 's/^[0-9a-f]\{64\}  //'; }

# 1. exact-hash copies
echo
echo "[*] Exact SHA256 matches (identical binaries):"
awk -v h="$HASH" '$1==h' "$WORK/samesize" | strip_hash > "$WORK/exact"
if [[ -s "$WORK/exact" ]]; then
    while IFS= read -r f; do
        rf=$(readlink -f "$f" 2>/dev/null || echo "$f")
        if [[ "$rf" == "$TARGET" ]]; then
            echo "  [orig] $f"
        else
            echo "  [COPY] $f  ($(stat -c '%U:%G %a mtime=%y' "$f" 2>/dev/null))"
        fi
    done < "$WORK/exact" | cap
else
    echo "  None."
fi

# 2. same size, different hash (possible per-host rebuild)
echo
echo "[*] Same size ($SIZE bytes) but DIFFERENT hash (possible rebuild):"
awk -v h="$HASH" '$1!=h' "$WORK/samesize" | strip_hash > "$WORK/sizeonly"
if [[ -s "$WORK/sizeonly" ]]; then
    while IFS= read -r f; do
        echo "  [SIZE?] $f  ($(stat -c '%U:%G %a mtime=%y' "$f" 2>/dev/null))"
    done < "$WORK/sizeonly" | cap
else
    echo "  None."
fi

# 3. drop-time window
if [[ "${BEACON_MTIME_MIN:-0}" =~ ^[0-9]+$ ]] && [[ "${BEACON_MTIME_MIN:-0}" -gt 0 ]]; then
    W=$BEACON_MTIME_MIN
    start=$(date -d "@$((MTIME - W*60))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    end=$(date -d "@$((MTIME + W*60))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    echo
    echo "[*] Files modified within ${W}min of the beacon ($start .. $end):"
    if [[ -n "$start" && -n "$end" ]]; then
        find / \( "${PRUNE[@]}" \) -prune -o -type f -newermt "$start" ! -newermt "$end" \
            -printf '  [TIME] %p  (%u:%g %m mtime=%t)\n' 2>/dev/null | cap
    else
        echo "  (could not compute window - GNU date required)"
    fi
fi

# --- running processes (catches deleted-from-disk beacons) -------------------
echo
echo "[*] Checking running processes by exe hash..."
PROC_FOUND=0
for p in /proc/[0-9]*; do
    h=$(sha256sum "$p/exe" 2>/dev/null | awk '{print $1}')
    [[ "$h" == "$HASH" ]] || continue
    PROC_FOUND=1
    pid=${p#/proc/}
    exe=$(readlink "$p/exe" 2>/dev/null)
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    user=$(stat -c %U "$p" 2>/dev/null)
    echo "  [PROC] PID=$pid USER=$user EXE=$exe CMD=$cmd"
done
[[ $PROC_FOUND -eq 0 ]] && echo "  No matching processes."

echo
echo "[*] Done."
exit 0
