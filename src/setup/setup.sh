#!/bin/sh
set -e
set -x

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
                                    
                                                 S E T U P

                                                   v 2.0
EOF
    printf "%s" "${RESET}"
}

# Ensure running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use: sudo ./setup.sh"
    exit 1
fi

# Ensure FreeBSD version is 14.x
if ! freebsd-version | grep -q '^14'; then
    echo "This script is designed for FreeBSD 14.x. Exiting."
    exit 1
fi

# Ensure pkg is initialized
if ! pkg -N > /dev/null 2>&1; then
    echo "Initializing pkg..."
    /usr/sbin/pkg bootstrap -y
fi

update_system_packages() {
    printf "\033[1;31m[+] Updating FreeBSD base and packages...\033[0m\n"
    freebsd-update fetch install || true
    pkg update -f && pkg upgrade -y
}

set_generic_hostname() {
    printf "\033[1;31m[+] Setting generic hostname...\033[0m\n"
    hostname "HARDN-VM"
    sysrc hostname="HARDN-VM"
}

install_base_packages() {
    printf "\033[1;31m[+] Installing base packages...\033[0m\n"
    pkg install -y bash sudo python3 py39-pip firejail nano wget curl git gawk lynis aide chkrootkit clamav
}

install_security_tools() {
    printf "\033[1;31m[+] Installing security tools...\033[0m\n"
    pkg install -y pf auditdistd security/auditd security/pam_pwquality security/openssh-portable
}

call_grub_script() {
    GRUB_SCRIPT="./grub.sh"  # Define path if not already

    printf "\033[1;31m[+] Calling grub.sh script...\033[0m\n"
    if [ -f "$GRUB_SCRIPT" ]; then
        printf "\033[1;31m[+] Setting executable permissions for grub.sh...\033[0m\n"
        chmod +x "$GRUB_SCRIPT"
        if ! "$GRUB_SCRIPT"; then
            printf "\033[1;31m[-] grub.sh execution failed. Exiting setup.\033[0m\n"
            exit 1
        fi
    else
        printf "\033[1;31m[-] grub.sh not found at: %s. Exiting setup.\033[0m\n" "$GRUB_SCRIPT"
        exit 1
    fi
}

configure_pf_firewall() {
    printf "\033[1;31m[+] Configuring PF firewall with strict defaults (SSH blocked)...\033[0m\n"

    PF_CONF="/etc/pf.conf"
    BACKUP_DIR="/var/backups/compliance"
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    BACKUP_FILE="${BACKUP_DIR}/pf.conf.bak.${TIMESTAMP}"

    mkdir -p "$BACKUP_DIR"

    if [ -f "$PF_CONF" ]; then
        cp "$PF_CONF" "$BACKUP_FILE"
        printf "\033[1;32m[+] Backed up existing pf.conf to %s\033[0m\n" "$BACKUP_FILE"
    fi

    cat > "$PF_CONF" <<EOF
# HARDN - Secure PF Configuration (SSH Blocked)

# Macros
ext_if = "vtnet0"

# Defaults
set skip on lo

# Block all inbound traffic including SSH
block in all

# Explicitly block SSH even if future rules are added
block in proto tcp to port 22

# Allow all outbound traffic
pass out all keep state
EOF

    if sysrc -q pf_enable="YES"; then
        printf "\033[1;32m[+] PF enabled in rc.conf\033[0m\n"
    else
        printf "\033[1;31m[-] Failed to enable PF in rc.conf\033[0m\n"
        exit 1
    fi

    if service pf restart; then
        printf "\033[1;32m[+] PF firewall restarted successfully\033[0m\n"
    else
        printf "\033[1;31m[-] PF firewall failed to restart\033[0m\n"
        exit 1
    fi
}

enable_auditd() {
    printf "\033[1;31m[+] Enabling auditd service...\033[0m\n"
    sysrc auditd_enable="YES"
    service auditd start
}

configure_aide() {
    printf "\033[1;31m[+] Configuring AIDE...\033[0m\n"
    aide --init
    mv /var/db/aide/aide.db.new /var/db/aide/aide.db
}

setup_fail2ban_like_behavior() {
    printf "\033[1;31m[+] Setting sshguard (Fail2Ban equivalent)...\033[0m\n"
    pkg install -y sshguard
    sysrc sshguard_enable="YES"
    service sshguard start
}

harden_sysctl() {
    printf "\033[1;31m[+] Applying sysctl hardening...\033[0m\n"
    cat <<EOF >> /etc/sysctl.conf

# Disable IP forwarding
net.inet.ip.forwarding=0

# Disable ICMP redirects
net.inet.ip.redirect=0
net.inet6.ip6.redirect=0

# Enable blackhole for TCP and UDP
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1

# Randomize PIDs to make process enumeration harder
kern.randompid=1

# Restrict visibility of other users' processes
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0

# Prevent unprivileged users from reading kernel message buffer
security.bsd.unprivileged_read_msgbuf=0

# Harden against SYN flood attacks
net.inet.tcp.syncookies=1

# Limit the size of the listen queue to prevent DoS
net.inet.tcp.msl=7500
net.inet.tcp.recvspace=65536
net.inet.tcp.sendspace=65536

# Disable source routing
net.inet.ip.sourceroute=0
net.inet6.ip6.sourceroute=0

# Log martian packets
net.inet.ip.check_interface=1

# Disable acceptance of router advertisements
net.inet6.ip6.accept_rtadv=0

# Enable stricter memory protections
vm.pmap.pg_ps_enabled=0
EOF
    sysctl -p
}


secure_boot_services() {
    printf "\033[1;31m[+] Disabling unnecessary services at boot...\033[0m\n"
    sysrc sendmail_enable="NONE"
    sysrc rpcbind_enable="NO"
    sysrc ntpd_enable="NO"
    sysrc avahi_daemon_enable="NO"
    sysrc cups_enable="NO"
}

secure_sshd() {
    printf "\033[1;31m[+] Hardening SSHD...\033[0m\n"
    sed -i '' -e 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i '' -e 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i '' -e 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sysrc sshd_enable="YES"
    service sshd restart
}

harden_password_policy() {
    printf "\033[1;31m[+] Setting password complexity policies...\033[0m\n"
    pw policy set enforce_pw_history=1 pw_history_len=5 min_pw_len=14 || echo "Password policy command failed. Ensure 'pw' supports these options."
}

set_randomize_va_space() {
    printf "\033[1;31m[+] Enabling ASLR...\033[0m\n"
    sysctl kern.elf64.aslr.enable=1
    echo "kern.elf64.aslr.enable=1" >> /etc/sysctl.conf
}

disable_core_dumps() {
    printf "\033[1;31m[+] Disabling core dumps...\033[0m\n"
    sysrc dumpdev="NO"
}

set_login_banners() {
    printf "\033[1;31m[+] Setting legal login banners...\033[0m\n"
    echo "You are accessing a SIG Information System. Unauthorized use is prohibited." > /etc/motd
}

install_rust() {
    printf "\033[1;31m[+] Installing Rust...\033[0m\n"
    if command -v rustc > /dev/null 2>&1; then
        printf "\033[1;32m[+] Rust already installed.\033[0m\n"
    else
        curl https://sh.rustup.rs -sSf | sh -s -- -y
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
}

update_firmware_tools() {
    printf "\033[1;31m[+] Updating firmware tools...\033[0m\n"
    pkg install -y dmidecode smartmontools
}

apply_stig_hardening() {
    set_generic_hostname
    configure_pf_firewall
    enable_auditd
    configure_aide
    setup_fail2ban_like_behavior
    harden_sysctl
    secure_boot_services
    secure_sshd
    harden_password_policy
    set_randomize_va_space
    disable_core_dumps
    set_login_banners
    install_rust
    update_firmware_tools
}

setup_complete() {
    echo "======================================================="
    echo "             [+] HARDN-FreeBSD Setup Complete         "
    echo "======================================================="
}

call_packages_script() {
    PACKAGES_SCRIPT="/HARDN/src/setup/packages.sh"
    printf "\033[1;31m[+] Looking for packages.sh at: %s\033[0m\n" "$PACKAGES_SCRIPT"
    if [ -f "$PACKAGES_SCRIPT" ]; then
        printf "\033[1;31m[+] Setting executable permissions for packages.sh...\033[0m\n"
        chmod +x "$PACKAGES_SCRIPT"
        printf "\033[1;31m[+] Calling packages.sh...\033[0m\n"
        "$PACKAGES_SCRIPT"
    else
        printf "\033[1;31m[-] packages.sh not found at: %s. Skipping...\033[0m\n" "$PACKAGES_SCRIPT"
    fi
}

main() {
    update_system_packages
    install_base_packages
    install_security_tools
    apply_stig_hardening
    setup_complete
    call_packages_script
}

main