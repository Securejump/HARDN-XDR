#!/bin/bash

OUTPUT_DIR="/root/Desktop"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
CSV_FILE="${OUTPUT_DIR}/lynis_report_${TIMESTAMP}.csv"
LYNIS_REPORT_FILE="/var/log/lynis-report.dat"


if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi


if ! command -v lynis &> /dev/null; then
        echo "Error: 'lynis' command not found. Please install Lynis first." >&2
        exit 1
fi


if ! mkdir -p "${OUTPUT_DIR}"; then
        echo "Error: Could not create output directory ${OUTPUT_DIR}." >&2
        exit 1
fi



echo "Starting Lynis system audit. This may take several minutes..."

lynis audit system --quiet

if [ ! -f "${LYNIS_REPORT_FILE}" ]; then
        echo "Error: Lynis report file not found at ${LYNIS_REPORT_FILE} after audit." >&2
        exit 1
fi

echo "Audit complete. Exporting results to ${CSV_FILE}..."

echo "key,value" > "${CSV_FILE}"

sed 's/=/,/' "${LYNIS_REPORT_FILE}" >> "${CSV_FILE}"

if [ $? -eq 0 ]; then
        echo "Successfully exported Lynis report to: ${CSV_FILE}"
else
        echo "Error: Failed to export report to CSV." >&2
        exit 1
fi

exit 0
