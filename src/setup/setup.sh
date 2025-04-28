#!/bin/sh
set -e
set -x

########################################
#       HARDN- FreeBSD - Setup         #
#        FreeBSD VM Version            #
#        STIG Compliant Setup          #
#  Hardened BSD 14.x - VM Optimized    #
#     Must have Python3 installed      #
#              Author                  #              #
#           - Tim Burns                #
#        Date: 4/28/2025               #
########################################

# Ensure running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use: sudo ./setup.sh"
    exit 1
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

configure_pf_firewall() {
    printf "\033[1;31m[+] Configuring PF Firewall...\033[0m\n"
    echo "block in all" > /etc/pf.conf
    echo "pass out all keep state" >> /etc/pf.conf
    sysrc pf_enable="YES"
    service pf restart
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

net.inet.ip.forwarding=0
net.inet.ip.redirect=0
net.inet6.ip6.redirect=0
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1
kern.randompid=1
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.bsd.unprivileged_read_msgbuf=0
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
    sed -i '' 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i '' 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i '' 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sysrc sshd_enable="YES"
    service sshd restart
}

harden_password_policy() {
    printf "\033[1;31m[+] Setting password complexity policies...\033[0m\n"
    pw policy set enforce_pw_history=1 pw_history_len=5 min_pw_len=14
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