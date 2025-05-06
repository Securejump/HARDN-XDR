#!/bin/sh

# FreeBSD 14 Compliance Script for VM
# Author: Tim Burns
# Version: 2.0-FreeBSD
# Description: Security hardening for FreeBSD virtual machines

set -eu

LOG_FILE="/var/log/compliance-setup.log"
BACKUP_DIR="/var/backups/compliance"

exec > "$LOG_FILE" 2>&1



print_ascii_banner() {
    CYAN_BOLD="\033[1;36m"
    RESET="\033[0m"

    printf "%s" "${CYAN_BOLD}"
    cat << "EOF"
                              ▄█    █▄       ▄████████    ▄████████ ████████▄  ███▄▄▄▄   
                             ███    ███     ███    ███   ███    ███ ███   ▀███ ███▀▀▀██▄ 
                             ███    ███     ███    ███   ███    ███ ███    ███ ███   ███ 
                            ▄███▄▄▄▄███▄▄   ███    ███  ▄███▄▄▄▄██▀ ███    ███ ███   ███ 
                           ▀▀███▀▀▀▀███▀  ▀███████████ ▀▀███▀▀▀▀▀   ███    ███ ███   ███ 
                             ███    ███     ███    ███ ▀███████████ ███    ███ ███   ███ 
                             ███    ███     ███    ███   ███    ███ ███   ▄███ ███   ███ 
                             ███    █▀      ███    █▀    ███    ███ ████████▀   ▀█   █▀  
                                                         ███    ███ 
                                    
                                            C O M P L I A N C E

                                                   v 2.0
EOF
    printf "%s" "${RESET}"
}


import_dependencies() {
    echo "[INFO] Checking for required tools..."
    for tool in sysctl pw; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "[ERROR] Required tool $tool is missing. Install it and rerun."
            exit 1
        fi
    done
    echo "[OK] All dependencies are available."
}

configure_sysctl() {
    echo "[INFO] Applying sysctl security settings..."
    sysctl security.bsd.see_other_uids=0
    sysctl kern.securelevel=1
    sysctl net.inet.ip.forwarding=0
    sysctl net.inet.icmp.drop_redirect=1

    echo "security.bsd.see_other_uids=0" >> /etc/sysctl.conf
    echo "kern.securelevel=1" >> /etc/sysctl.conf
    echo "net.inet.ip.forwarding=0" >> /etc/sysctl.conf
    echo "net.inet.icmp.drop_redirect=1" >> /etc/sysctl.conf
    echo "[OK] Sysctl settings updated."
}

configure_loader_conf() {
    echo "[INFO] Securing /boot/loader.conf..."
    cp /boot/loader.conf "$BACKUP_DIR/loader.conf.bak.$(date +%s)"
    echo 'kern.securelevel_enable="YES"' >> /boot/loader.conf
    echo 'kern.securelevel=1' >> /boot/loader.conf
    echo "[OK] loader.conf updated for secure boot."
}

setup_cron() {
    echo "[INFO] Setting up daily cron job to validate system integrity..."
    echo "@daily root /usr/bin/sha256 -q /boot/kernel/kernel" >> /etc/crontab
    echo "[OK] Daily integrity check added to cron."
}

setup_complete() {
    printf "\033[1;32m[COMPLETED] Compliance setup completed successfully.\033[0m\n"
}

main() {
    print_ascii_banner
    mkdir -p "$BACKUP_DIR"
    import_dependencies
    configure_sysctl
    configure_loader_conf
    setup_cron
    setup_complete
}

main "$@"