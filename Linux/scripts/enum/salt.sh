#!/bin/sh
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# salt.sh - show SaltStack minion/master configuration and keys. Read-only.
# Exits 0 when Salt is not installed so coordinate does not count it as a failure.

MINION=false
MASTER=false
[ -f /etc/salt/minion ] && MINION=true
[ -f /etc/salt/master ] && MASTER=true

if [ "$MINION" = false ] && [ "$MASTER" = false ]; then
    echo "SaltStack is not installed."
    exit 0
fi

# show_conf <file>  -> non-comment, non-blank lines (skips missing files quietly)
show_conf() {
    [ -f "$1" ] || return 0
    echo "--- $1"
    grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1"
}

# resolve <name>  -> what this host would resolve it to (getent includes /etc/hosts)
resolve() {
    if command -v getent >/dev/null 2>&1; then
        getent hosts "$1" || echo "(getent: $1 does not resolve)"
    fi
    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$1" 2>&1
    elif command -v dig >/dev/null 2>&1; then
        dig +short "$1" 2>&1
    elif ! command -v getent >/dev/null 2>&1; then
        echo "(no getent, nslookup or dig available)"
    fi
}

if [ "$MINION" = true ]; then
    echo "Salt Minion is installed."
    echo "Checking for master configuration..."
    show_conf /etc/salt/minion
    for f in /etc/salt/minion.d/*.conf; do show_conf "$f"; done
    if [ -f /etc/salt/minion_id ]; then
        echo "--- /etc/salt/minion_id"
        cat /etc/salt/minion_id
    fi
    echo "Salt DNS (salt):"
    resolve salt
    echo "Salt DNS (salt.salt):"
    resolve salt.salt
fi

if [ "$MASTER" = true ]; then
    echo "Salt Master is installed."
    if command -v salt-key >/dev/null 2>&1; then
        echo "Accepted Keys:"
        salt-key -L
    fi
    echo "Master Configuration:"
    show_conf /etc/salt/master
    for f in /etc/salt/master.d/*.conf; do show_conf "$f"; done
    echo "Existing Salt Files:"
    if [ -d /srv/salt ]; then ls -alR /srv/salt; else echo "(/srv/salt does not exist)"; fi
    if command -v salt-run >/dev/null 2>&1; then
        echo "Minion Status:"
        salt-run manage.status
    fi
    if command -v salt >/dev/null 2>&1; then
        salt '*' test.ping
    fi
fi
exit 0
