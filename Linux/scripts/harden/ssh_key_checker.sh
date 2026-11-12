#!/bin/sh
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# Show (and optionally wipe + lock) every SSH authorized_keys file.
#   WIPE_KEYS=1   empty each file and make it immutable (chattr +i / chflags uchg)
# Covers: every home in /etc/passwd, authorized_keys AND authorized_keys2,
# custom AuthorizedKeysFile paths from `sshd -T`, and a filesystem sweep.
# The sweep can take a while on big disks: use coordinate -T 120 or more.

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

say() { printf "$1%s${NC}\n" "$2"; }

if [ "$(id -u)" -ne 0 ]; then
    say "$RED" "[!] This script must be run as root or with sudo"
    exit 1
fi

SEEN_FILE=$(mktemp /tmp/sshkeys.XXXXXX) || exit 1
trap 'rm -f "$SEEN_FILE"' EXIT

SSHD_BIN=$(command -v sshd 2>/dev/null)
for c in /usr/sbin/sshd /usr/local/sbin/sshd; do
    [ -n "$SSHD_BIN" ] && break
    [ -x "$c" ] && SSHD_BIN=$c
done

unlock_file() {
    if command -v chattr >/dev/null 2>&1; then
        chattr -i -a "$1" 2>/dev/null
    elif command -v chflags >/dev/null 2>&1; then
        chflags nouchg,noschg,nouappnd,nosappnd "$1" 2>/dev/null
    fi
}

lock_file() {
    if command -v chattr >/dev/null 2>&1; then
        chattr +i "$1" 2>/dev/null
    elif command -v chflags >/dev/null 2>&1; then
        # uchg, not schg: schg can't be cleared at securelevel > 0 without a reboot
        chflags uchg "$1" 2>/dev/null
    else
        return 1
    fi
}

wipe_and_lock() {
    file="$1"
    [ -n "$WIPE_KEYS" ] || return 0
    say "$RED" "[!] WIPE_KEYS is set - Wiping and locking: $file"
    # Never write through a symlink (authorized_keys -> /etc/shadow would wipe shadow)
    if [ -L "$file" ]; then
        say "$YELLOW" "[!] $file is a symlink to $(readlink "$file") - removing the link instead"
        rm -f "$file"
        return 0
    fi
    # Red team often sets +i/+a first, which makes a plain wipe fail silently
    unlock_file "$file"
    if ! : > "$file" 2>/dev/null; then
        say "$RED" "[-] FAILED to wipe $file (still immutable? read-only fs?)"
        return 1
    fi
    if lock_file "$file"; then
        say "$GREEN" "[+] Successfully wiped and locked: $file"
    else
        say "$YELLOW" "[!] Wiped but could not set immutable flag: $file"
    fi
    echo ""
}

# Show + optionally wipe a file once, no matter how many ways we found it
check_file() {
    file="$1"; label="$2"
    [ -f "$file" ] || return 0
    grep -qxF "$file" "$SEEN_FILE" && return 0
    echo "$file" >> "$SEEN_FILE"
    say "$GREEN" "[+] $label: $file"
    if [ -s "$file" ]; then
        say "$YELLOW" "Contents:"
        cat "$file"
    else
        echo "(empty)"
    fi
    echo ""
    wipe_and_lock "$file"
}

# Expand AuthorizedKeysFile tokens (%h home, %u user, %% literal) for one user
expand_akf() {
    pattern="$1"; home="$2"; user="$3"
    for p in $pattern; do
        [ "$p" = none ] && continue
        p=$(printf '%s' "$p" | sed -e "s|%%|\\\\045|g" -e "s|%h|$home|g" -e "s|%u|$user|g" -e 's|\\045|%|g')
        case "$p" in
            /*) echo "$p" ;;
            *)  echo "$home/$p" ;;    # relative paths are relative to $HOME
        esac
    done
}

check_user_keys() {
    say "$BLUE" "--- Checking every account's home directory ---"
    AKF=""
    if [ -n "$SSHD_BIN" ]; then
        AKF=$("$SSHD_BIN" -T 2>/dev/null | awk 'tolower($1)=="authorizedkeysfile" {$1=""; print}')
    fi
    [ -n "$AKF" ] && say "$BLUE" "[*] sshd AuthorizedKeysFile:$AKF"

    # getent isn't on every BSD; /etc/passwd is the fallback
    { getent passwd 2>/dev/null || cat /etc/passwd; } | awk -F: '{print $1 ":" $6}' | \
    while IFS=: read -r user home; do
        [ -n "$home" ] && [ -d "$home" ] || continue
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2" \
                 $(expand_akf "$AKF" "$home" "$user"); do
            check_file "$f" "Keys for $user"
        done
    done
}

check_unusual_keys() {
    say "$BLUE" "--- Searching for authorized_keys* anywhere else ---"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o \
        -type f -name 'authorized_keys*' -print 2>/dev/null | while read -r file; do
        grep -qxF "$file" "$SEEN_FILE" && continue
        say "$YELLOW" "[!] Found authorized_keys in unusual location: $file"
        check_file "$file" "Unusual"
    done
}

show_conf() {
    say "$YELLOW" "Configuration file: $1"
    echo "=========================================="
    grep -v -E '^[[:space:]]*(#|$)' "$1"
    echo "=========================================="
    echo ""
}

check_ssh_config() {
    say "$YELLOW" "[*] Checking SSH configuration files..."
    echo ""

    for cfg in /etc/ssh/sshd_config /usr/local/etc/ssh/sshd_config; do
        [ -f "$cfg" ] || continue
        show_conf "$cfg"
        if [ -d "$cfg.d" ]; then
            for f in "$cfg.d"/*; do
                [ -f "$f" ] && show_conf "$f"
            done
        fi
    done

    if [ -n "$SSHD_BIN" ]; then
        say "$BLUE" "--- Effective key-related settings (sshd -T) ---"
        "$SSHD_BIN" -T 2>/dev/null | grep -iE '^(pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|authorizedprincipals|trustedusercakeys|permitrootlogin|passwordauthentication) '
        echo ""
    fi
}

MAIN() {
    say "$BLUE" "========================================"
    say "$BLUE" "  SSH Enumeration Script"
    say "$BLUE" "========================================"
    echo ""

    say "$GREEN" "[+] Starting enumeration..."
    if [ -n "$WIPE_KEYS" ]; then
        say "$RED" "[!] WARNING: WIPE_KEYS is set - All found authorized_keys files will be wiped and locked!"
    fi
    echo ""

    check_user_keys
    check_unusual_keys

    say "$GREEN" "[+] SSH authorized_keys enumeration complete"
    echo ""

    check_ssh_config

    say "$GREEN" "[+] SSH configuration enumeration complete"
    say "$BLUE" "========================================"
    say "$BLUE" "  Enumeration Complete"
    say "$BLUE" "========================================"
}

MAIN
