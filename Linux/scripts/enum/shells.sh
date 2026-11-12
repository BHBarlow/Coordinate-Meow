#!/bin/sh
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# shells.sh - hash every shell in /etc/passwd and /etc/shells, then look for
# copies of those shells anywhere else on disk (a renamed copy of bash is an
# easy way to keep a hidden shell). Read-only.
#
# Does ONE filesystem walk, only hashing files whose size matches a shell, and
# skips /proc, /sys, container/snap image stores and network mounts.

WORK=$(mktemp -d "${TMPDIR:-/tmp}/shells.XXXXXX") || { echo "mktemp failed"; exit 1; }
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' INT TERM

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | cut -d' ' -f1
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1" 2>/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
    fi
}
# size of the file a path points at (follows symlinks like /bin/sh -> dash)
file_size() { stat -L -c %s "$1" 2>/dev/null || stat -L -f %z "$1" 2>/dev/null; }
real_path() { readlink -f "$1" 2>/dev/null || realpath "$1" 2>/dev/null || echo "$1"; }

if [ -z "$(hash_file /etc/passwd)" ]; then
    echo "No sha256sum, sha256 or shasum available - cannot hash shells"
    exit 0
fi

# known: one line per shell -> "<hash> <size> <real path> <listed path>"
KNOWN=$WORK/known
: > "$KNOWN"
add_shell() {
    [ -f "$1" ] || return 0
    h=$(hash_file "$1")
    s=$(file_size "$1")
    [ -n "$h" ] && [ -n "$s" ] || return 0
    echo "[+] $1 hash: $h"
    echo "$h $s $(real_path "$1") $1" >> "$KNOWN"
}

echo "Checking for hashes of all shells in /etc/passwd"
echo "======="
cut -f7 -d':' /etc/passwd | sort -u > "$WORK/passwd_shells"
while IFS= read -r shell; do
    [ -n "$shell" ] && add_shell "$shell"
done < "$WORK/passwd_shells"
echo "======="

echo "Checking for hashes of all shells in /etc/shells"
echo "======="
if [ -f /etc/shells ]; then
    grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' /etc/shells > "$WORK/etc_shells"
    while IFS= read -r shell; do
        add_shell "$shell"
    done < "$WORK/etc_shells"
fi
echo "======="

if [ ! -s "$KNOWN" ]; then
    echo "No shell binaries found to compare against"
    exit 0
fi

# Two listed shells that are different files but have the same hash means one was
# overwritten with a copy of the other, e.g. /usr/sbin/nologin or /bin/false replaced
# by bash so a "disabled" account still gets a shell. (Symlinks like /bin/sh -> dash
# resolve to the same real file and are not reported.)
echo "Checking whether any listed shell is a copy of another"
echo "======="
awk '!(($1 SUBSEP $3) in seen) { seen[$1 SUBSEP $3] = 1; n[$1]++; paths[$1] = paths[$1] " " $3 }
     END { for (h in n) if (n[h] > 1) print h paths[h] }' "$KNOWN" > "$WORK/dups"
if [ -s "$WORK/dups" ]; then
    while read -r h paths; do
        echo "[!] These are the SAME binary (sha256 $h) - one has probably been replaced:"
        for p in $paths; do ls -li "$p" 2>/dev/null; done
    done < "$WORK/dups"
else
    echo "[+] Every listed shell is a distinct binary"
fi
echo "======="

# Build: find / ( -path P1 -o -path P2 ... ) -prune -o -type f ( -size Ac -o -size Bc ... ) -print
set -- /proc /sys /snap /var/lib/snapd/snap /var/lib/docker /var/lib/containers /var/lib/lxcfs
if [ -r /proc/mounts ]; then
    while read -r _dev mp fs _rest; do
        case $fs in
            nfs|nfs4|cifs|smb3|smbfs|fuse.sshfs|9p|ceph|glusterfs|fuse.s3fs|fuse.rclone|autofs) set -- "$@" "$mp" ;;
        esac
    done < /proc/mounts
fi
skipped="$*"
first=1
for p in "$@"; do
    if [ "$first" -eq 1 ]; then set -- \( -path "$p"; first=0; else set -- "$@" -o -path "$p"; fi
done
set -- "$@" \) -prune -o -type f \(
first=1
for s in $(cut -d' ' -f2 "$KNOWN" | sort -u); do
    if [ "$first" -eq 1 ]; then set -- "$@" -size "${s}c"; first=0; else set -- "$@" -o -size "${s}c"; fi
done
set -- "$@" \) -print

echo "Searching the filesystem for other files with the same hash as a shell"
echo "(skipping: $skipped)"
echo "======="
find / "$@" 2>/dev/null > "$WORK/candidates"
copies=0
while IFS= read -r f; do
    h=$(hash_file "$f")
    [ -n "$h" ] || continue
    grep -q "^$h " "$KNOWN" || continue
    rp=$(real_path "$f")
    # the shell binary itself (e.g. /usr/bin/bash behind the /bin/bash symlink) is not a copy
    awk -v h="$h" -v rp="$rp" '$1 == h && $3 == rp {found=1} END {exit !found}' "$KNOWN" && continue
    same_as=$(awk -v h="$h" '$1 == h {print $4}' "$KNOWN" | sort -u | tr '\n' ' ')
    echo "[!] $f is a copy of: $same_as"
    ls -l "$f" 2>/dev/null
    copies=$((copies + 1))
done < "$WORK/candidates"
[ "$copies" -eq 0 ] && echo "[+] No copies of shells found outside their real location"
echo "======="
exit 0
