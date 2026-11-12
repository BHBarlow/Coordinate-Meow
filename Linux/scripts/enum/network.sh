#!/bin/sh
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# network.sh - firewall rules + listening/established sockets in one pass.
# Combines fw_status.sh and display_port_connections.sh. Read-only.
#
# Shows every firewall layer present (pf, ipfw, nftables, iptables/ip6tables,
# ufw, firewalld) and every listening + established socket. Exits 0 when a
# given tool is absent so coordinate does not count the host as failed.
#
# Colour is only emitted to a real terminal, so coordinate's saved output files
# stay free of raw escape codes.

if [ -t 1 ]; then
    GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    GREEN=''; CYAN=''; YELLOW=''; NC=''
fi

# printf interprets the \033 escapes on every POSIX sh (echo does not, portably)
say()    { printf '%b\n' "$*"; }
header() { printf '%b\n' "${CYAN}========== $1${NC}"; }
title()  { printf '\n%b\n' "${GREEN}[+] $1${NC}"; }

# find_bin <name>  -> full path, also checking sbin dirs a sudo PATH may lack
find_bin() {
    command -v "$1" 2>/dev/null && return 0
    for d in /sbin /usr/sbin /usr/local/sbin; do
        [ -x "$d/$1" ] && { echo "$d/$1"; return 0; }
    done
    return 1
}

[ "$(id -u)" -eq 0 ] || say "${YELLOW}[!] Not running as root - most firewall and socket listings need root (coordinate: add -S)${NC}"

# ============================================================
# Firewalls
# ============================================================
title "Firewall rules"
fw_found=0

if pf=$(find_bin pfctl); then
    fw_found=1
    header "pf rules ($pf -s rules)"
    "$pf" -s rules 2>&1
    header "pf info"
    "$pf" -s info 2>&1
fi

if ipfw=$(find_bin ipfw); then
    fw_found=1
    header "ipfw rules ($ipfw list)"
    "$ipfw" list 2>&1
fi

if nft=$(find_bin nft); then
    fw_found=1
    header "nftables ($nft list ruleset)"
    "$nft" list ruleset 2>&1
fi

if ipt=$(find_bin iptables); then
    fw_found=1
    header "iptables filter ($ipt -vnL)"
    "$ipt" -vnL 2>&1
    header "iptables nat ($ipt -t nat -vnL)"
    "$ipt" -t nat -vnL 2>&1
fi

if ip6t=$(find_bin ip6tables); then
    fw_found=1
    header "ip6tables filter ($ip6t -vnL)"
    "$ip6t" -vnL 2>&1
fi

if ufw=$(find_bin ufw); then
    fw_found=1
    header "ufw ($ufw status verbose)"
    "$ufw" status verbose 2>&1
fi

if fwc=$(find_bin firewall-cmd); then
    fw_found=1
    header "firewalld ($fwc)"
    if "$fwc" --state >/dev/null 2>&1; then
        echo "--- active zones"
        "$fwc" --get-active-zones 2>&1
        echo "--- default zone"
        "$fwc" --list-all 2>&1
    else
        echo "firewalld is installed but not running"
    fi
fi

[ "$fw_found" -eq 0 ] && say "${YELLOW}NO FIREWALL TOOLS FOUND (pfctl, ipfw, nft, iptables, ufw, firewall-cmd), GOOD LUCK${NC}"

# ============================================================
# Sockets
# ============================================================
# BSD: sockstat. Linux: ss (preferred) or netstat.
if sockstat=$(find_bin sockstat); then
    LIST_CMD="$sockstat -l"
    ESTB_CMD="$sockstat -46c"
elif ss=$(find_bin ss); then
    LIST_CMD="$ss -blunt -p"
    ESTB_CMD="$ss -tunp state established"
elif netstat=$(find_bin netstat); then
    LIST_CMD="$netstat -tulpn"
    ESTB_CMD="$netstat -tunp"
fi

if [ -z "$LIST_CMD" ]; then
    say "${YELLOW}No ss, sockstat or netstat found - cannot list sockets${NC}"
    exit 0
fi

title "Listening sockets"
header "$LIST_CMD"
$LIST_CMD 2>&1

title "Established connections"
header "$ESTB_CMD"
$ESTB_CMD 2>&1

exit 0
