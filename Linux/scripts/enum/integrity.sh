#!/bin/sh
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# integrity.sh - verify installed packages against the distro's manifest
# (changed files, bad perms/owner, missing files). Read-only.
#   INTEGRITY_MAX  max lines to print (default 2000, 0 = no limit)

MAX=${INTEGRITY_MAX:-2000}
case $MAX in ''|*[!0-9]*) MAX=2000 ;; esac
cap() { if [ "$MAX" -eq 0 ]; then cat; else
    awk -v m="$MAX" 'NR<=m; NR==m+1{print "    ... capped at "m" lines (INTEGRITY_MAX=0 for all)"}'
fi; }

found=0
if command -v debsums >/dev/null 2>&1; then
    found=1
    echo "[+] debsums -ca (changed files, including config):"
    debsums -ca 2>/dev/null | cap
fi
if command -v rpm >/dev/null 2>&1; then
    found=1
    echo "[+] rpm -Va (S=sum M=mode 5=md5 U=user G=group T=time, c=config):"
    rpm -Va 2>/dev/null | cap
fi
[ "$found" -eq 0 ] && echo "No debsums or rpm available - cannot verify package integrity"
exit 0
