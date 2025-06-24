#!/bin/bash

set -euo pipefail

HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
REPORT_FILE="/tmp/system_health_${HOSTNAME}.html"

TOTAL_MEM=$(free | awk '/Mem:/ {print $2}')
USED_MEM=$(free | awk '/Mem:/ {print $3}')
MEM_PCT=$(( USED_MEM * 100 / TOTAL_MEM ))

LOAD_AVG_1M=$(awk '{print $1}' /proc/loadavg)
NUM_CORES=$(nproc)
LOAD_HIGH=$(echo "$LOAD_AVG_1M > $NUM_CORES" | bc)

{
echo "<!DOCTYPE html>"
echo "<html lang='en'>"
echo "<head><meta charset='UTF-8'><title>System Health Report</title>"
echo "<style>
    body { font-family: Arial, sans-serif; background: #f8f9fa; color: #212529; padding: 20px; }
    h2 { background: #343a40; color: #fff; padding: 10px; border-radius: 5px; }
    h3 { border-bottom: 1px solid #ccc; margin-top: 30px; }
    pre { background: #e9ecef; padding: 10px; border-left: 5px solid #adb5bd; overflow-x: auto; }
    .alert { color: #721c24; background-color: #f8d7da; padding: 10px; border-left: 5px solid #dc3545; border-radius: 3px; margin-top: 10px; }
    .section { margin-top: 30px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    table, th, td { border: 1px solid #dee2e6; }
    th, td { padding: 8px; text-align: left; }
    th { background-color: #343a40; color: #fff; }
    .highlight { background-color: #fff3cd; }
</style>
</head>
<body>"

echo "<h2>🖥️ System Health Report for $HOSTNAME</h2>"
echo "<p><strong>Generated at:</strong> $TIMESTAMP</p>"

### CPU
echo "<div class='section'><h3>⚙️ CPU Load</h3><pre>"
uptime
echo "</pre>"

if [ "$LOAD_HIGH" -eq 1 ]; then
    echo "<div class='alert'>🚨 High CPU Load: $LOAD_AVG_1M > $NUM_CORES cores</div><pre>"
    ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6
    echo "</pre>"
fi
echo "</div>"

### Memory
echo "<div class='section'><h3>🧠 Memory Usage</h3><pre>"
free -h
echo "</pre>"

if [ "$MEM_PCT" -ge 85 ]; then
    echo "<div class='alert'>🚨 High Memory Usage: $MEM_PCT%</div><pre>"
    ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -n 6
    echo "</pre>"
fi
echo "</div>"

### Disk
echo "<div class='section'><h3>💾 Disk Usage</h3><pre>"
df -hT
echo "</pre>"

OVERUSED_MOUNTS=$(df -hP | awk '$5+0 >= 85 {print $6}')
if [ -n "$OVERUSED_MOUNTS" ]; then
    echo "<div class='alert'>🚨 Mounts with >85% usage detected</div>"
    for MOUNT in $OVERUSED_MOUNTS; do
        echo "<h4>$MOUNT</h4><pre>"
        find "$MOUNT" -type f -printf '%s %p\n' 2>/dev/null | sort -nr | head -n 10 | awk '{printf "%.1f MB\t%s\n", $1/1024/1024, $2}'
        echo "</pre>"
    done
fi
echo "</div>"

### Network
echo "<div class='section'><h3>🌐 Network I/O</h3><pre>"
awk '/:/ { printf "%-10s RX: %10s bytes  |  TX: %10s bytes\n", $1, $2, $10 }' /proc/net/dev
echo "</pre></div>"

### Top Processes
echo "<div class='section'><h3>🔥 Top Processes by CPU</h3><pre>"
ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6
echo "</pre>"

echo "<h3>🔥 Top Processes by Memory</h3><pre>"
ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -n 6
echo "</pre></div>"

echo "</body></html>"
} > "$REPORT_FILE"

if [ -s "$REPORT_FILE" ]; then
    echo "[+] Styled HTML report generated at: $REPORT_FILE"
else
    echo "[-] Failed to create report." >&2
    exit 1
fi
