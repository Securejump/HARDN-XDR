#!/bin/bash

LOGFILE="/var/log/hardn-daemon.log"

echo "[INFO] HARDN-XDR Daemon started at $(date)" >> "$LOGFILE"

while true; do
    
    /usr/lib/hardn-xdr/src/setup/hardn-audit.sh >> "$LOGFILE" 2>&1
    sleep 106000
done
