#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald
# KaliPatriot | TTU CCDC | Landon Byrge
#
# Back up PAM config + modules, verify them against the package database, and
# optionally reinstall PAM. Options are env vars (coordinate -E):
#   (none)        back up /etc/pam.d and PAM modules to $BCK, then verify
#   REINSTALL=1   back up, then reinstall PAM packages and regenerate config
#   REVERT=1      restore /etc/pam.d and modules from the backup
#   DISFW=1       temporarily open outbound firewall for the package manager
#                 (restored to its previous state on exit)
#   UNTESTED=1    allow running on Alpine / Slackware / Arch
#   BCK           backup root (default /root/.cache)
#
# Reinstalls download packages: raise coordinate's timeout, e.g. -T 300.
# NOTE: package reinstalls do NOT overwrite modified files in /etc/pam.d (dpkg
# and rpm keep admin-changed config files). Check the verify output for those.

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Must run as root."
    exit 1
fi

BCK="${BCK:-/root/.cache}"
BACKUPCONFDIR="$BCK/pam.d"
BACKUPBINARYDIR="$BCK/pam_libraries"

ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)

case "$(uname -s)" in
    *BSD|DragonFly) IS_BSD=true ;;
    *) IS_BSD=false ;;
esac

# ── Firewall open/close around package installs ────────────────────────────
FW_OPENED=""
ALLOW() {
    [ -z "$DISFW" ] && return
    if [ "$IS_BSD" = true ]; then
        if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
            pfctl -d && FW_OPENED=pf
        fi
    elif [ -n "$ipt" ]; then
        if $ipt -S OUTPUT 2>/dev/null | grep -q '^-P OUTPUT DROP'; then
            $ipt -P OUTPUT ACCEPT && FW_OPENED=ipt
        fi
    fi
    [ -n "$FW_OPENED" ] && echo "[!] Outbound firewall temporarily opened."
}

DENY() {
    case "$FW_OPENED" in
        pf)  pfctl -e ;;
        ipt) $ipt -P OUTPUT DROP ;;
        *)   return ;;
    esac
    FW_OPENED=""
    echo "[+] Outbound firewall restored."
}

# Always put the firewall back, even if we exit early
trap 'DENY' EXIT
trap 'exit 1' HUP INT TERM

# ── Backup / revert ─────────────────────────────────────────────────────────
backup_pam() {
    echo "[+] Backing up PAM configuration files and binaries..."

    if [ -d /etc/pam.d ]; then
        mkdir -p "$BACKUPCONFDIR"
        cp -Rp /etc/pam.d/. "$BACKUPCONFDIR/"
    fi
    # FreeBSD/OpenBSD may also use /etc/pam.conf
    [ -f /etc/pam.conf ] && cp -p /etc/pam.conf "$BCK/pam.conf"

    mkdir -p "$BACKUPBINARYDIR"
    MOD=$(find /lib/ /lib64/ /lib32/ /usr/lib/ /usr/lib64/ /usr/lib32/ /usr/local/lib/ \
        -name "pam_unix.so*" 2>/dev/null)

    if [ -z "$MOD" ]; then
        echo "[-] pam_unix.so not found"
    else
        echo "[+] Found the following pam_unix.so files:"
        echo "$MOD"
        for i in $MOD; do
            BINARY_DIR=$(dirname "$i")
            DEST="$BACKUPBINARYDIR$BINARY_DIR"
            echo "Backing up all binaries from $BINARY_DIR to $DEST"
            mkdir -p "$DEST"
            cp -p "$BINARY_DIR"/pam* "$DEST/" 2>/dev/null
        done
    fi

    echo "[+] Backup complete: $BCK"
}

revert_pam() {
    echo "[+] Reverting PAM binaries from backup..."
    if [ ! -d "$BACKUPBINARYDIR" ]; then
        echo "[-] Backup directory $BACKUPBINARYDIR does not exist. Cannot revert."
        exit 1
    fi
    find "$BACKUPBINARYDIR" -type f | while read -r file; do
        ORIGINAL_DIR=$(dirname "${file#"$BACKUPBINARYDIR"}")
        echo "Restoring $file to $ORIGINAL_DIR"
        mkdir -p "$ORIGINAL_DIR"
        cp -p "$file" "$ORIGINAL_DIR/"
    done

    echo "[+] Reverting PAM configuration files..."
    if [ ! -d "$BACKUPCONFDIR" ]; then
        echo "[-] Backup directory $BACKUPCONFDIR does not exist. Cannot revert."
        exit 1
    fi
    cp -Rp "$BACKUPCONFDIR"/. /etc/pam.d/
    [ -f "$BCK/pam.conf" ] && cp -p "$BCK/pam.conf" /etc/pam.conf

    echo "[+] Reversion complete."
}

# ── Package-database verification (read-only) ───────────────────────────────
verify_pam() {
    echo "[+] Verifying PAM files against the package database..."
    echo "    (5 = checksum changed, c = config file; any output here is worth a look)"
    if command -v dpkg >/dev/null 2>&1; then
        PKGS=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'libpam*' 2>/dev/null \
            | awk '$1 ~ /^ii/ {print $2}' | tr '\n' ' ')
        # Never call dpkg -V with no args: that verifies EVERY package
        [ -z "$PKGS" ] && { echo "    [*] No libpam packages found."; return; }
        # shellcheck disable=SC2086
        OUT=$(dpkg -V $PKGS 2>&1)
    elif command -v rpm >/dev/null 2>&1; then
        OUT=$(rpm -V pam 2>&1)
    else
        echo "    [*] No dpkg/rpm here; skipping verification."
        return
    fi
    if [ -n "$OUT" ]; then
        echo "$OUT"
    else
        echo "    [+] No modified PAM package files."
    fi
}

# ── Per-distro reinstall ────────────────────────────────────────────────────
DEBIAN() {
    echo "[+] Reinstalling PAM-related packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get -y -o Dpkg::Options::=--force-confold --reinstall install \
        libpam-runtime libpam-modules libpam-modules-bin </dev/null
    # Regenerate common-* from the package profiles (drops injected lines)
    pam-auth-update --package --force </dev/null
    echo "[+] Reinstallation complete."
}

RHEL() {
    echo "[+] Reinstalling PAM-related packages..."
    if command -v dnf >/dev/null 2>&1; then
        dnf -y reinstall pam
    else
        yum -y reinstall pam
    fi
    if command -v authselect >/dev/null 2>&1; then
        # RHEL 8+: regenerate system-auth/password-auth if authselect manages them
        if authselect check >/dev/null 2>&1; then
            authselect apply-changes
        else
            echo "[!] authselect is not managing PAM here (or files were edited). Review /etc/pam.d by hand."
        fi
    elif command -v authconfig >/dev/null 2>&1; then
        authconfig --updateall
    fi
    echo "[+] Reinstallation complete."
}

SUSE() {
    echo "[+] Reinstalling PAM-related packages..."
    zypper --non-interactive install -f pam
    pam-config --update
    echo "[+] Reinstallation complete."
}

ALPINE() {
    echo "[+] Reinstalling PAM-related packages for Alpine..."
    apk fix --reinstall linux-pam
    find /etc/pam.d -name '*.apk-new' 2>/dev/null | while read -r file; do
        mv "$file" "${file%.apk-new}"
    done
    echo "[+] Reinstallation complete."
}

SLACK() {
    echo "[!] Slackware does not support automatic reinstallation of packages. Please reinstall PAM manually."
}

ARCH() {
    echo "[+] Reinstalling PAM-related packages for Arch..."
    pacman -S --noconfirm pam
    echo "[+] Reinstallation complete."
}

BSD() {
    # PAM is part of the FreeBSD/OpenBSD base system, not a package.
    echo "[!] PAM is in the BSD base system; it can't be reinstalled with pkg."
    echo "    FreeBSD: compare with 'freebsd-update IDS' or restore from install media."
}

need_untested() {
    if [ -z "$UNTESTED" ]; then
        echo "[-] $1 is untested. Set UNTESTED=1 after testing manually."
        exit 1
    fi
}

reinstall_pam() {
    ALLOW
    if [ "$IS_BSD" = true ]; then
        BSD
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        RHEL
    elif command -v zypper >/dev/null 2>&1; then
        SUSE
    elif command -v apt-get >/dev/null 2>&1; then
        DEBIAN   # Ubuntu included
    elif command -v apk >/dev/null 2>&1; then
        need_untested "Alpine Linux"; ALPINE
    elif command -v slapt-get >/dev/null 2>&1 || grep -qi slackware /etc/os-release 2>/dev/null; then
        need_untested "Slackware"; SLACK
    elif command -v pacman >/dev/null 2>&1; then
        need_untested "Arch Linux"; ARCH
    else
        echo "[-] Unknown package manager; cannot reinstall PAM."
    fi
    DENY
}

# ── Main ────────────────────────────────────────────────────────────────────
if [ -n "$REVERT" ]; then
    revert_pam
    exit 0
fi

# Back up BEFORE touching anything so a bad reinstall can be reverted.
backup_pam

if [ -n "$REINSTALL" ]; then
    reinstall_pam
fi

verify_pam
