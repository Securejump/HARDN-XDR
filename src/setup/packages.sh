#!/bin/sh
set -e
set -x

########################################
# HARDN - Packages - FreeBSD Version   #
# THIS SCRIPT IS STIG COMPLIANT         #
# Must have repo cloned beforehand      #
# Author(s):                            #
#  - Chris Bingham                      #
#  - Tim Burns                          #
# Date: 4/28/2025                       #
########################################

# Ensure script runs as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use: sudo ./packages.sh"
    exit 1
fi

LOG_FILE="/var/log/hardn_packages.log"
FIX_MODE=false

initialize_log() {
    echo "========================================" > "$LOG_FILE"
    echo " HARDN - Packages Validation Log" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "[+] Log initialized at $(date)" >> "$LOG_FILE"
}

fix_if_needed() {
    check_cmd="$1"
    fix_cmd="$2"
    success_msg="$3"
    failure_msg="$4"

    if eval "$check_cmd"; then
        echo "[+] $success_msg" | tee -a "$LOG_FILE"
    else
        echo "[-] $failure_msg" | tee -a "$LOG_FILE"
        if $FIX_MODE; then
            echo "[*] Attempting to fix..." | tee -a "$LOG_FILE"
            if eval "$fix_cmd"; then
                echo "[+] Fixed: $success_msg" | tee -a "$LOG_FILE"
            else
                echo "[-] Failed to fix: $failure_msg" | tee -a "$LOG_FILE"
            fi
        fi
    fi
}

validate_stig_hardening() {
    echo "[+] Validating STIG compliance..." | tee -a "$LOG_FILE"

    fix_if_needed \
        "grep -q 'kern.elf64.aslr.enable=1' /etc/sysctl.conf" \
        "echo 'kern.elf64.aslr.enable=1' >> /etc/sysctl.conf && sysctl kern.elf64.aslr.enable=1" \
        "ASLR is enabled" \
        "ASLR not enabled"

    fix_if_needed \
        "grep -q 'security.bsd.see_other_uids=0' /etc/sysctl.conf" \
        "echo 'security.bsd.see_other_uids=0' >> /etc/sysctl.conf && sysctl security.bsd.see_other_uids=0" \
        "UID privacy enforced" \
        "UID privacy not enforced"

    fix_if_needed \
        "grep -q 'security.bsd.see_other_gids=0' /etc/sysctl.conf" \
        "echo 'security.bsd.see_other_gids=0' >> /etc/sysctl.conf && sysctl security.bsd.see_other_gids=0" \
        "GID privacy enforced" \
        "GID privacy not enforced"

    fix_if_needed \
        "[ ! -z \"\$(grep 'Unauthorized use is prohibited' /etc/motd)\" ]" \
        "echo 'Unauthorized use is prohibited.' > /etc/motd" \
        "MOTD legal banner exists" \
        "MOTD legal banner missing"
}

validate_packages() {
    echo "[+] Validating package configurations..." | tee -a "$LOG_FILE"

    command -v pfctl >/dev/null &&
    echo "[+] pf (firewall) installed." | tee -a "$LOG_FILE" ||
    echo "[-] pf not installed." | tee -a "$LOG_FILE"

    service pf status >/dev/null 2>&1 &&
    echo "[+] pf firewall active." | tee -a "$LOG_FILE" ||
    echo "[-] pf firewall not active." | tee -a "$LOG_FILE"

    command -v aide >/dev/null &&
    echo "[+] AIDE installed." | tee -a "$LOG_FILE" ||
    echo "[-] AIDE not installed." | tee -a "$LOG_FILE"

    command -v chkrootkit >/dev/null &&
    echo "[+] chkrootkit installed." | tee -a "$LOG_FILE" ||
    echo "[-] chkrootkit not installed." | tee -a "$LOG_FILE"

    service auditd status >/dev/null 2>&1 &&
    echo "[+] auditd running." | tee -a "$LOG_FILE" ||
    echo "[-] auditd not running." | tee -a "$LOG_FILE"

    command -v sshguard >/dev/null &&
    echo "[+] sshguard (Fail2ban equivalent) installed." | tee -a "$LOG_FILE" ||
    echo "[-] sshguard not installed." | tee -a "$LOG_FILE"

    service sshguard status >/dev/null 2>&1 &&
    echo "[+] sshguard active." | tee -a "$LOG_FILE" ||
    echo "[-] sshguard not active." | tee -a "$LOG_FILE"

    command -v firejail >/dev/null &&
    echo "[+] firejail installed." | tee -a "$LOG_FILE" ||
    echo "[-] firejail not installed." | tee -a "$LOG_FILE"
}

validate_configuration() {
    printf "\033[1;31m[+] Validating configuration...\033[0m\n"

    validate_packages
    validate_stig_hardening

    echo -e "\033[1;32m[+] ======== VALIDATION COMPLETE =========\033[0m" | tee -a "$LOG_FILE"
    $FIX_MODE && echo -e "\033[1;34m[*] Fix mode was enabled. Auto-remediation attempted.\033[0m" | tee -a "$LOG_FILE"
}

make_immutable() {
    SETUP_SCRIPT="/HARDN/src/setup/setup.sh"
    PACKAGES_SCRIPT="/HARDN/src/setup/packages.sh"

    printf "\033[1;31m[+] Making setup.sh and packages.sh immutable...\033[0m\n"
    chmod 555 "$SETUP_SCRIPT"
    chmod 555 "$PACKAGES_SCRIPT"
    chflags schg "$SETUP_SCRIPT"
    chflags schg "$PACKAGES_SCRIPT"
    printf "\033[1;32m[+] setup.sh and packages.sh are now immutable.\033[0m\n"
}

main() {
    if [ "$1" = "--fix" ]; then
        FIX_MODE=true
    fi

    initialize_log
    validate_configuration
    make_immutable

    # Force reboot
    printf "\033[1;31m[+] Rebooting system...\033[0m\n"
    shutdown -r now || printf "\033[1;31m[-] Reboot failed. Please reboot manually.\033[0m\n"
}

main "$@"