#!/usr/bin/env bash
# ==============================================================================
# Sentient Endpoint Defense - Linux Installation Script
# https://github.com/Sentient/Sentient
# ==============================================================================

set -euo pipefail

# ANSI color codes
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
DATA_DIR="${PREFIX}/share/sentient"
SYSCONF_DIR="/etc/sentient"
APPS_DIR="/usr/share/applications"
ICONS_DIR="/usr/share/icons/hicolor/256x256/apps"
PIXMAPS_DIR="/usr/share/pixmaps"
POLKIT_DIR="/usr/share/polkit-1/actions"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_BIN="${SCRIPT_DIR}/sentient"
SOURCE_SIGS="${SCRIPT_DIR}/signatures.json"
SOURCE_LOGO="${SCRIPT_DIR}/logo.png"
SOURCE_DESKTOP="${SCRIPT_DIR}/sentient.desktop"
SOURCE_POLKIT="${SCRIPT_DIR}/org.sentient.security.policy"

# Fallback paths if run from source repository
if [[ ! -f "${SOURCE_BIN}" ]]; then
    if [[ -f "${SCRIPT_DIR}/../../target/x86_64-unknown-linux-musl/release/sentient" ]]; then
        SOURCE_BIN="${SCRIPT_DIR}/../../target/x86_64-unknown-linux-musl/release/sentient"
    fi
fi
if [[ ! -f "${SOURCE_SIGS}" ]]; then
    if [[ -f "${SCRIPT_DIR}/../../signatures.json" ]]; then
        SOURCE_SIGS="${SCRIPT_DIR}/../../signatures.json"
    fi
fi
if [[ ! -f "${SOURCE_LOGO}" ]]; then
    if [[ -f "${SCRIPT_DIR}/../../assets/logo.png" ]]; then
        SOURCE_LOGO="${SCRIPT_DIR}/../../assets/logo.png"
    fi
fi

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ███████╗███████╗███╗   ██╗████████╗██╗███████╗███╗   ██╗████████╗"
    echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝████╗  ██║╚══██╔══╝"
    echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║█████╗  ██╔██╗ ██║   ██║   "
    echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██╔══╝  ██║╚██╗██║   ██║   "
    echo "  ███████║███████╗██║ ╚████║   ██║   ██║███████╗██║ ╚████║   ██║   "
    echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   "
    echo -e "         ${GREEN}High-Performance Offline Endpoint Security${NC}"
    echo
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${AMBER}[!] Sentient requires root privileges for system-wide installation.${NC}"
        echo -e "${CYAN}[*] Requesting sudo credentials...${NC}"
        exec sudo bash "$0" "$@"
    fi
}

install_sentient() {
    echo -e "${CYAN}[*] Starting Sentient Endpoint Defense installation...${NC}"

    if [[ ! -f "${SOURCE_BIN}" ]]; then
        echo -e "${RED}[ERROR] Binary '${SOURCE_BIN}' not found. Please build or unpack first.${NC}"
        exit 1
    fi

    # 1. Create target directories
    echo -e "  -> Creating directories..."
    mkdir -p "${BIN_DIR}" "${DATA_DIR}" "${SYSCONF_DIR}" "${APPS_DIR}" "${ICONS_DIR}" "${PIXMAPS_DIR}"

    # 2. Install executable
    echo -e "  -> Installing binary to ${BIN_DIR}/sentient..."
    cp -f "${SOURCE_BIN}" "${BIN_DIR}/sentient"
    chmod 0755 "${BIN_DIR}/sentient"

    # 3. Install offline IOC signatures database
    if [[ -f "${SOURCE_SIGS}" ]]; then
        echo -e "  -> Installing threat intelligence signatures to ${SYSCONF_DIR}/signatures.json..."
        cp -f "${SOURCE_SIGS}" "${SYSCONF_DIR}/signatures.json"
        cp -f "${SOURCE_SIGS}" "${DATA_DIR}/signatures.json"
        chmod 0644 "${SYSCONF_DIR}/signatures.json" "${DATA_DIR}/signatures.json"
    fi

    # 4. Install logos and application icons
    if [[ -f "${SOURCE_LOGO}" ]]; then
        echo -e "  -> Installing icons..."
        mkdir -p "${ICONS_DIR}" "${PIXMAPS_DIR}"
        cp -f "${SOURCE_LOGO}" "${ICONS_DIR}/sentient.png"
        cp -f "${SOURCE_LOGO}" "${PIXMAPS_DIR}/sentient.png"
        chmod 0644 "${ICONS_DIR}/sentient.png" "${PIXMAPS_DIR}/sentient.png"
        for size in 16 24 32 48 64 128; do
            mkdir -p "/usr/share/icons/hicolor/${size}x${size}/apps"
            cp -f "${SOURCE_LOGO}" "/usr/share/icons/hicolor/${size}x${size}/apps/sentient.png" 2>/dev/null || true
        done
    fi

    # 5. Install FreeDesktop .desktop entry
    if [[ -f "${SOURCE_DESKTOP}" ]]; then
        echo -e "  -> Installing application launcher to ${APPS_DIR}/sentient.desktop..."
        cp -f "${SOURCE_DESKTOP}" "${APPS_DIR}/sentient.desktop"
        chmod 0644 "${APPS_DIR}/sentient.desktop"

        # Also place desktop launcher on Desktop if ~/Desktop exists
        REAL_USER="${SUDO_USER:-${USER:-}}"
        if [[ -n "${REAL_USER}" && "${REAL_USER}" != "root" ]]; then
            USER_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6 || true)"
            if [[ -n "${USER_HOME}" && -d "${USER_HOME}/Desktop" ]]; then
                echo -e "  -> Creating Desktop shortcut at ${USER_HOME}/Desktop/sentient.desktop..."
                cp -f "${SOURCE_DESKTOP}" "${USER_HOME}/Desktop/sentient.desktop"
                chown "${REAL_USER}:${REAL_USER}" "${USER_HOME}/Desktop/sentient.desktop" 2>/dev/null || true
                chmod 0755 "${USER_HOME}/Desktop/sentient.desktop" 2>/dev/null || true
            fi
        fi
    fi

    # 6. Install PolicyKit elevation policy
    if [[ -d "${POLKIT_DIR}" && -f "${SOURCE_POLKIT}" ]]; then
        echo -e "  -> Installing PolicyKit action policy..."
        cp -f "${SOURCE_POLKIT}" "${POLKIT_DIR}/org.sentient.security.policy"
        chmod 0644 "${POLKIT_DIR}/org.sentient.security.policy"
    fi

    # 7. Generate clean uninstaller
    cat > "${BIN_DIR}/sentient-uninstall" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi
echo "Uninstalling Sentient Endpoint Defense..."
rm -f /usr/local/bin/sentient
rm -f /usr/local/bin/sentient-uninstall
rm -rf /usr/local/share/sentient
rm -rf /etc/sentient
rm -f /usr/share/applications/sentient.desktop
rm -f /home/*/Desktop/sentient.desktop 2>/dev/null || true
rm -f /root/Desktop/sentient.desktop 2>/dev/null || true
rm -f /usr/share/icons/hicolor/256x256/apps/sentient.png
rm -f /usr/share/pixmaps/sentient.png
rm -f /usr/share/polkit-1/actions/org.sentient.security.policy

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f /usr/share/icons/hicolor || true
fi
echo "Sentient has been successfully uninstalled."
EOF
    chmod 0755 "${BIN_DIR}/sentient-uninstall"

    # 8. Refresh desktop databases and icon caches
    echo -e "  -> Refreshing desktop database and icon caches..."
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "${APPS_DIR}" 2>/dev/null || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -f -t "/usr/share/icons/hicolor" 2>/dev/null || true
    fi

    echo
    echo -e "${GREEN}${BOLD}✔ Sentient has been installed successfully!${NC}"
    echo -e "  Binary:       ${CYAN}${BIN_DIR}/sentient${NC}"
    echo -e "  Signatures:   ${CYAN}${SYSCONF_DIR}/signatures.json${NC}"
    echo -e "  Uninstaller:  ${CYAN}${BIN_DIR}/sentient-uninstall${NC}"
    echo
    echo -e "You can launch Sentient from your application menu, or run:"
    echo -e "  ${BOLD}sentient${NC}               (Standard mode)"
    echo -e "  ${BOLD}pkexec sentient${NC}        (Elevated Administrator mode)"
    echo
}

main() {
    print_banner
    check_root "$@"
    install_sentient
}

main "$@"
