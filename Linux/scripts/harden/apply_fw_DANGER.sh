#!/bin/sh
# thanks @d_tranman/Nigel Gerald/Nigerald
# KaliPatriot was here, but can someone tell me what the hell is going on here?
# Foister is just happy to be here
#
# Default-deny firewall (iptables on Linux, pf on the BSDs).
# Run through coordinate with -E, e.g.:
#   coordinate -t HOSTS -u root -p PASS \
#     -E DISPATCHER=10.0.0.5 -E LOCALNETWORK=10.0.0.0/24 -E CCSHOST=1.2.3.4 \
#     -E ALLOW_TCP=80,443 Linux/scripts/harden/apply_fw_DANGER.sh
#
# Env vars:
#   DISPATCHER    (required) host(s) allowed in on SSH (comma list ok)
#   LOCALNETWORK  (required) network(s) allowed in/out (comma list ok)
#   CCSHOST       scoring/CCS host(s) allowed in/out; required unless NOTNATS=1
#   ALLOW_TCP     comma list of TCP ports open to ANY source (scored services)
#   ALLOW_UDP     comma list of UDP ports open to ANY source (e.g. 53)
#   KEEP_V6=1     do not lock down IPv6 (default: IPv6 is dropped except lo)
#   BCK           backup dir (default /root/.cache)
#
# A safety cron flushes the firewall in ~4-5 minutes and every 5 minutes after.
# Run Linux/scripts/misc/remove_fw_cron.sh once you confirm you're not locked out.

ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
ip6t=$(command -v ip6tables || command -v /sbin/ip6tables || command -v /usr/sbin/ip6tables)
ipts=$(command -v iptables-save || command -v /sbin/iptables-save || command -v /usr/sbin/iptables-save)

case "$(uname -s)" in
    *BSD|DragonFly) IS_BSD=true ;;
    *) IS_BSD=false ;;
esac

ALLOW() {
    if [ "$IS_BSD" = true ]; then
        pfctl -d
        pfctl -F all
    else
        $ipt -P INPUT ACCEPT; $ipt -P OUTPUT ACCEPT; $ipt -P FORWARD ACCEPT; $ipt -F; $ipt -X
        if [ -n "$ip6t" ] && [ -z "$KEEP_V6" ]; then
            $ip6t -P INPUT ACCEPT; $ip6t -P OUTPUT ACCEPT; $ip6t -P FORWARD ACCEPT; $ip6t -F; $ip6t -X
        fi
    fi
}

CHECKERR() {
    if [ ! $? -eq 0 ]; then
        echo "ERROR, EXITTING TO PREVENT LOCKOUT"
        ALLOW
        exit 1
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root (use coordinate -S or log in as root)."
    exit 1
fi

if [ -z "$ipt" ] && [ "$IS_BSD" = false ]; then
    echo "NO IPTABLES ON THIS SYSTEM, NOT BSD, GOOD LUCK"
    exit 1
fi

if [ -z "$DISPATCHER" ]; then
    echo "DISPATCHER not defined."
    exit 1
fi

if [ -z "$LOCALNETWORK" ]; then
    echo "LOCALNETWORK not defined."
    exit 1
fi

if [ -z "$CCSHOST" ] && [ -z "$NOTNATS" ]; then
    echo "CCSHOST not defined and WE ARE AT NATS BRO!"
    exit 1
fi

BCK="${BCK:-/root/.cache}"
mkdir -p "$BCK" 2>/dev/null

if [ -f /etc/ufw/ufw.conf ] && command -v ufw >/dev/null 2>&1; then
    ufw disable
fi

if [ -f /etc/firewalld/firewalld.conf ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop firewalld
    systemctl disable firewalld
fi

# ── Safety flush cron ───────────────────────────────────────────────────────
FW_FLUSH_COMMENT="# COORD_FW_SAFETY_FLUSH"
if [ "$IS_BSD" = true ]; then
    FW_FLUSH_CMD="pfctl -d; pfctl -F all"
else
    FW_FLUSH_CMD="$ipt -P INPUT ACCEPT; $ipt -P OUTPUT ACCEPT; $ipt -P FORWARD ACCEPT; $ipt -F; $ipt -X"
    if [ -n "$ip6t" ] && [ -z "$KEEP_V6" ]; then
        FW_FLUSH_CMD="$FW_FLUSH_CMD; $ip6t -P INPUT ACCEPT; $ip6t -P OUTPUT ACCEPT; $ip6t -P FORWARD ACCEPT; $ip6t -F; $ip6t -X"
    fi
fi

# `*/5` can fire seconds after we apply the rules. Phase the 5-minute cycle off
# the current minute so the first flush lands ~4-5 minutes from now.
NOW_MIN=$(date +%M); NOW_MIN=${NOW_MIN#0}
PHASE=$(( NOW_MIN % 5 ))
CRON_MINS="$PHASE"
m=$(( PHASE + 5 ))
while [ "$m" -lt 60 ]; do CRON_MINS="$CRON_MINS,$m"; m=$(( m + 5 )); done

if command -v crontab >/dev/null 2>&1; then
    # Remove any existing safety flush cron before adding a fresh one
    ( crontab -l 2>/dev/null | grep -v "COORD_FW_SAFETY_FLUSH" ; echo "$CRON_MINS * * * * $FW_FLUSH_CMD $FW_FLUSH_COMMENT" ) | crontab -
    echo "[!] SAFETY CRON INSTALLED: Firewall will be flushed every 5 minutes (first in ~4-5 min)."
    echo "[!] Run misc/remove_fw_cron.sh once connectivity is confirmed."
else
    # No cron available: one-shot detached flush in 5 minutes.
    nohup sh -c "sleep 300; $FW_FLUSH_CMD" >/dev/null 2>&1 </dev/null &
    echo "[!] crontab not found: ONE-SHOT flush scheduled in 5 minutes (PID $!)."
    echo "[!] kill $! once connectivity is confirmed."
fi

if [ "$IS_BSD" = false ]; then
    if [ -n "$ipts" ]; then
        $ipts > /opt/rules.v4.old 2>/dev/null
        $ipts > "$BCK/rules.v4.old"
    fi

    ALLOW

    # Replies to traffic we allowed. Non-fatal: very old kernels may lack conntrack.
    $ipt -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        $ipt -A INPUT  -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    $ipt -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        $ipt -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null

    if [ -n "$CCSHOST" ]; then
        $ipt -A OUTPUT -d "$CCSHOST" -j ACCEPT
        CHECKERR
        $ipt -A INPUT -s "$CCSHOST" -j ACCEPT
        CHECKERR
    fi

    # Allow local network
    $ipt -A INPUT -s "$LOCALNETWORK" -j ACCEPT
    CHECKERR
    $ipt -A OUTPUT -d "$LOCALNETWORK" -j ACCEPT
    CHECKERR

    # Allow loopback
    $ipt -A INPUT -i lo -j ACCEPT
    CHECKERR
    $ipt -A OUTPUT -o lo -j ACCEPT
    CHECKERR

    # Allow in SSH from dispatcher
    $ipt -A INPUT -s "$DISPATCHER" -p tcp --dport 22 -j ACCEPT
    CHECKERR
    $ipt -A OUTPUT -d "$DISPATCHER" -p tcp --sport 22 -j ACCEPT
    CHECKERR

    # Scored services open to anyone
    for p in $(echo "$ALLOW_TCP" | tr ',' ' '); do
        $ipt -A INPUT -p tcp --dport "$p" -j ACCEPT
        CHECKERR
        $ipt -A OUTPUT -p tcp --sport "$p" -j ACCEPT
        CHECKERR
    done
    for p in $(echo "$ALLOW_UDP" | tr ',' ' '); do
        $ipt -A INPUT -p udp --dport "$p" -j ACCEPT
        CHECKERR
        $ipt -A OUTPUT -p udp --sport "$p" -j ACCEPT
        CHECKERR
    done

    # Block everything else
    $ipt -P INPUT DROP
    CHECKERR
    $ipt -P OUTPUT DROP
    CHECKERR
    $ipt -P FORWARD DROP
    CHECKERR

    # IPv6: nothing above applies to v6, so without this it stays wide open.
    if [ -n "$ip6t" ] && [ -z "$KEEP_V6" ]; then
        $ip6t -F; $ip6t -X
        $ip6t -A INPUT -i lo -j ACCEPT
        $ip6t -A OUTPUT -o lo -j ACCEPT
        $ip6t -P INPUT DROP
        $ip6t -P OUTPUT DROP
        $ip6t -P FORWARD DROP
        echo "[+] IPv6 locked down (lo only). Set KEEP_V6=1 to skip."
    fi

    # Save rules
    if [ -n "$ipts" ]; then
        $ipts > /opt/rules.v4
        $ipts > "$BCK/rules.v4"
        $ipts
    else
        $ipt -S
    fi
else
    ALLOW

    [ -f /etc/pf.conf ] && cp /etc/pf.conf "$BCK/pf.conf.old"

    {
        echo "set skip on lo"
        for i in $(echo "$DISPATCHER" | tr ',' ' '); do
            echo "pass in quick proto tcp from $i to any port 22"
        done
        for i in $(echo "$LOCALNETWORK" | tr ',' ' '); do
            echo "pass in quick from $i to any"
            echo "pass out quick from any to $i"
        done
        for i in $(echo "$CCSHOST" | tr ',' ' '); do
            echo "pass out quick from any to $i"
            echo "pass in quick from $i to any"
        done
        for p in $(echo "$ALLOW_TCP" | tr ',' ' '); do
            echo "pass in quick proto tcp from any to any port $p"
        done
        for p in $(echo "$ALLOW_UDP" | tr ',' ' '); do
            echo "pass in quick proto udp from any to any port $p"
        done
        echo "block all"
    } > /etc/pf.conf.coord

    # Validate before installing so a typo can't leave us half-applied
    if ! pfctl -nf /etc/pf.conf.coord; then
        echo "ERROR: generated pf.conf failed validation; leaving firewall OPEN."
        rm -f /etc/pf.conf.coord
        exit 1
    fi
    mv /etc/pf.conf.coord /etc/pf.conf
    cat /etc/pf.conf

    # FreeBSD needs the module; OpenBSD has pf built in (no kldload)
    command -v kldload >/dev/null 2>&1 && kldload -n pf 2>/dev/null
    pfctl -f /etc/pf.conf
    CHECKERR
    pfctl -e
    CHECKERR
fi
