#!/bin/bash
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | TTU CCDC | Behnjamin Barlow

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Cron Jobs Enumeration Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}[!] Warning: Not running as root. Some cron files may not be accessible${NC}" 
   echo ""
fi

echo -e "${GREEN}[+] Starting cron enumeration...${NC}"
echo ""

#############################################
# System-wide Crontab
#############################################

echo -e "${YELLOW}[*] /etc/crontab${NC}"
if [ -f /etc/crontab ]; then
    cat /etc/crontab
    echo ""
else
    echo -e "${RED}[-] Not found${NC}"
fi

#############################################
# /etc/cron.d/ Directory
#############################################

echo -e "${YELLOW}[*] /etc/cron.d/${NC}"
if [ -d /etc/cron.d ]; then
    ls -altr /etc/cron.d/
    echo ""
    
    # Show contents if CROND is not set
    if [ -z "$CROND" ]; then
        for file in /etc/cron.d/*; do
            if [ -f "$file" ]; then
                echo -e "${BLUE}$file:${NC}"
                cat "$file"
                echo ""
            fi
        done
    fi
else
    echo -e "${RED}[-] Not found${NC}"
fi

#############################################
# Daily Cron Jobs
#############################################

echo -e "${YELLOW}[*] /etc/cron.daily/${NC}"
if [ -d /etc/cron.daily ]; then
    ls -altr /etc/cron.daily/
    echo ""
else
    echo -e "${RED}[-] Not found${NC}"
fi

#############################################
# User Crontabs
#############################################

echo -e "${YELLOW}[*] User crontabs (/var/spool/cron/)${NC}"
if [ -d /var/spool/cron ]; then
    # Check for individual user crontabs
    if [ -d /var/spool/cron/crontabs ]; then
        find /var/spool/cron/crontabs/ -type f 2>/dev/null | while read -r file; do
            echo -e "${BLUE}$file:${NC}"
            cat "$file" 2>/dev/null
            echo ""
        done
    fi
    
    # Also check direct files in /var/spool/cron/ (some systems use this)
    find /var/spool/cron/ -maxdepth 1 -type f 2>/dev/null | while read -r file; do
        echo -e "${BLUE}$file:${NC}"
        cat "$file" 2>/dev/null
        echo ""
    done
else
    echo -e "${RED}[-] Not found${NC}"
fi

#############################################
# All Users' Crontabs (if root)
#############################################

if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[*] All users' crontabs${NC}"
    
    # Get all users from /etc/passwd
    while IFS=: read -r username _ _ _ _ _ _; do
        crontab -u "$username" -l 2>/dev/null && {
            echo -e "${BLUE}User: $username${NC}"
            crontab -u "$username" -l 2>/dev/null
            echo ""
        }
    done < /etc/passwd
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Cron Enumeration Complete${NC}"
echo -e "${BLUE}========================================${NC}"