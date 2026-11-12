#!/bin/bash
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# ssh_key_checker.sh (enum) - DISPLAY ONLY. Shows every authorized_keys file and
# the effective sshd configuration. It never changes anything on the host.
#
# To WIPE and lock attacker keys, use the hardening copy instead:
#   Linux/scripts/harden/ssh_key_checker.sh   (supports WIPE_KEYS=1)
#
# Colour is only emitted to a real terminal, so coordinate's saved output files
# stay free of raw escape codes.

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

show_keys() {
    # show_keys <authorized_keys file> <label>
    local file="$1" label="$2" line n=0
    echo "${BLUE}--- $label: $file ---${NC}"
    if [ ! -f "$file" ]; then
        echo "${YELLOW}[-] not present${NC}"
        echo ""
        return
    fi
    echo "${GREEN}[+] exists${NC} ($(stat -L -c '%U:%G %a' "$file" 2>/dev/null))"
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in ''|\#*) continue ;; esac
        n=$((n + 1))
        echo "    [$n] $line"
    done < "$file"
    [ "$n" -eq 0 ] && echo "    (no active key lines)"
    echo ""
}

check_root_keys() {
    show_keys "/root/.ssh/authorized_keys" "root"
    show_keys "/root/.ssh/authorized_keys2" "root (authorized_keys2)"
}

check_user_keys() {
    # Every home directory listed in /etc/passwd, not just /home/* - service
    # accounts (www-data, postgres, ...) often have homes elsewhere.
    echo "${BLUE}--- User authorized_keys (homes from /etc/passwd) ---${NC}"
    echo ""
    local user home seen=" /root "
    while IFS=: read -r user _ _ _ _ home _; do
        [ -n "$home" ] && [ -d "$home" ] || continue
        case $seen in *" $home "*) continue ;; esac
        seen="$seen$home "
        show_keys "$home/.ssh/authorized_keys" "$user"
        [ -f "$home/.ssh/authorized_keys2" ] && show_keys "$home/.ssh/authorized_keys2" "$user (authorized_keys2)"
    done < /etc/passwd
}

check_unusual_keys() {
    # authorized_keys files anywhere else on disk (attacker drop points)
    echo "${BLUE}--- Searching for authorized_keys in unusual locations ---${NC}"
    find / -xdev \( -path /proc -o -path /sys \) -prune -o \
        -type f -name 'authorized_keys*' -print 2>/dev/null | while IFS= read -r file; do
        case $file in
            /root/.ssh/authorized_keys|/root/.ssh/authorized_keys2) continue ;;
            /home/*/.ssh/authorized_keys|/home/*/.ssh/authorized_keys2) continue ;;
        esac
        echo "${YELLOW}[!] authorized_keys in unusual location: $file${NC}"
        show_keys "$file" "unusual"
    done
}

check_ssh_config() {
    echo "${YELLOW}[*] SSH server configuration${NC}"
    echo ""

    # Effective, fully-resolved config - covers Include, Match, and defaults that
    # a raw read of sshd_config misses. Needs sshd in PATH or a standard sbin dir.
    local sshd
    sshd=$(command -v sshd 2>/dev/null || { for d in /usr/sbin /sbin /usr/local/sbin; do [ -x "$d/sshd" ] && { echo "$d/sshd"; break; }; done; })
    if [ -n "$sshd" ]; then
        echo "${BLUE}--- Effective config ($sshd -T) ---${NC}"
        echo "=========================================="
        "$sshd" -T 2>/dev/null | grep -iE \
            'permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|permitemptypasswords|allowusers|allowgroups|denyusers|denygroups|forcecommand|usepam|x11forwarding|permittunnel|gatewayports' \
            || "$sshd" -T 2>/dev/null
        echo "=========================================="
        echo ""
    else
        echo "${YELLOW}[-] sshd binary not found - showing raw config files instead${NC}"
        echo ""
    fi

    # Raw files too, so you can see comments / commented-out directives
    if [ -f /etc/ssh/sshd_config ]; then
        echo "${BLUE}--- /etc/ssh/sshd_config (active lines) ---${NC}"
        echo "=========================================="
        grep -E '^[[:space:]]*[^#[:space:]]' /etc/ssh/sshd_config
        echo "=========================================="
        echo ""
    fi
    if [ -d /etc/ssh/sshd_config.d ]; then
        for file in /etc/ssh/sshd_config.d/*; do
            [ -f "$file" ] || continue
            echo "${BLUE}--- $file (active lines) ---${NC}"
            echo "=========================================="
            grep -E '^[[:space:]]*[^#[:space:]]' "$file"
            echo "=========================================="
            echo ""
        done
    fi
}

MAIN() {
    echo "${BLUE}========================================${NC}"
    echo "${BLUE}  SSH Key & Config Enumeration (display only)${NC}"
    echo "${BLUE}========================================${NC}"
    echo ""
    if [[ $EUID -ne 0 ]]; then
        echo "${YELLOW}[!] Not root - some homes and the sshd -T dump may be unreadable (coordinate: add -S)${NC}"
        echo ""
    fi

    check_root_keys
    check_user_keys
    check_unusual_keys
    check_ssh_config

    echo "${BLUE}========================================${NC}"
    echo "${BLUE}  Enumeration Complete${NC}"
    echo "${BLUE}========================================${NC}"
}

MAIN
