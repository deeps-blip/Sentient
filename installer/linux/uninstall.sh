#!/usr/bin/env bash
# ==============================================================================
# Sentient Endpoint Defense - Linux Uninstallation Script
# ==============================================================================

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Requesting root privileges to uninstall Sentient..."
    exec sudo bash "$0" "$@"
fi

echo "Removing Sentient components from system..."
rm -f /usr/local/bin/sentient
rm -f /usr/local/bin/sentient-uninstall
rm -rf /usr/local/share/sentient
rm -rf /etc/sentient
rm -f /usr/share/applications/sentient.desktop
rm -f /home/*/Desktop/sentient.desktop
rm -f /root/Desktop/sentient.desktop
rm -f /usr/share/icons/hicolor/256x256/apps/sentient.png
rm -f /usr/share/pixmaps/sentient.png
rm -f /usr/share/polkit-1/actions/org.sentient.security.policy

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi

echo "Sentient has been completely removed from this system."
