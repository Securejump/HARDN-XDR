HARDN_STATUS "pass" "Disabling unnecessary services..."

disable_service_if_active avahi-daemon
disable_service_if_active cups
disable_service_if_active rpcbind
disable_service_if_active nfs-server
disable_service_if_active smbd
disable_service_if_active snmpd
disable_service_if_active apache2
disable_service_if_active mysql
disable_service_if_active bind9


packages_to_remove="telnet vsftpd proftpd tftpd postfix exim4"
for pkg in $packages_to_remove; do
	if dpkg -s "$pkg" >/dev/null 2>&1; then
		HARDN_STATUS "error" "Removing package: $pkg..."
		apt remove -y "$pkg"
	else
		HARDN_STATUS "info" "Package $pkg not installed. Skipping removal."
	fi
done

HARDN_STATUS "pass" "Unnecessary services checked and disabled/removed where applicable."
