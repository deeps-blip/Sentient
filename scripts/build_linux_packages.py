#!/usr/bin/env python3
"""
Packages Sentient for Linux:
1. sentient-v1.0.0-linux-x86_64.tar.gz (Self-contained tarball with install.sh)
2. sentient_1.0.0_amd64.deb (Standard Debian/Ubuntu binary package)
"""

import os
import shutil
import tarfile
import io
import time
import gzip

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
LINUX_BIN = os.path.join(ROOT_DIR, "target", "x86_64-unknown-linux-musl", "release", "sentient")
SIGS_JSON = os.path.join(ROOT_DIR, "signatures.json")
LOGO_PNG = os.path.join(ROOT_DIR, "assets", "logo.png")
INSTALL_SH = os.path.join(ROOT_DIR, "installer", "linux", "install.sh")
UNINSTALL_SH = os.path.join(ROOT_DIR, "installer", "linux", "uninstall.sh")
DESKTOP_FILE = os.path.join(ROOT_DIR, "installer", "linux", "sentient.desktop")
POLKIT_FILE = os.path.join(ROOT_DIR, "installer", "linux", "org.sentient.security.policy")

def build_tarball():
    os.makedirs(DIST_DIR, exist_ok=True)
    tar_path = os.path.join(DIST_DIR, "sentient-v1.0.0-linux-x86_64.tar.gz")
    print(f"[*] Packaging {tar_path}...")

    with tarfile.open(tar_path, "w:gz") as tar:
        # Add binary with executable permissions
        bin_info = tar.gettarinfo(LINUX_BIN, arcname="sentient-v1.0.0-linux-x86_64/sentient")
        bin_info.mode = 0o755
        with open(LINUX_BIN, "rb") as f:
            tar.addfile(bin_info, f)

        # Add install script
        inst_info = tar.gettarinfo(INSTALL_SH, arcname="sentient-v1.0.0-linux-x86_64/install.sh")
        inst_info.mode = 0o755
        with open(INSTALL_SH, "rb") as f:
            tar.addfile(inst_info, f)

        # Add uninstall script
        uninst_info = tar.gettarinfo(UNINSTALL_SH, arcname="sentient-v1.0.0-linux-x86_64/uninstall.sh")
        uninst_info.mode = 0o755
        with open(UNINSTALL_SH, "rb") as f:
            tar.addfile(uninst_info, f)

        # Add signatures.json
        sig_info = tar.gettarinfo(SIGS_JSON, arcname="sentient-v1.0.0-linux-x86_64/signatures.json")
        sig_info.mode = 0o644
        with open(SIGS_JSON, "rb") as f:
            tar.addfile(sig_info, f)

        # Add logo
        logo_info = tar.gettarinfo(LOGO_PNG, arcname="sentient-v1.0.0-linux-x86_64/logo.png")
        logo_info.mode = 0o644
        with open(LOGO_PNG, "rb") as f:
            tar.addfile(logo_info, f)

        # Add desktop
        desk_info = tar.gettarinfo(DESKTOP_FILE, arcname="sentient-v1.0.0-linux-x86_64/sentient.desktop")
        desk_info.mode = 0o644
        with open(DESKTOP_FILE, "rb") as f:
            tar.addfile(desk_info, f)

        # Add polkit
        pol_info = tar.gettarinfo(POLKIT_FILE, arcname="sentient-v1.0.0-linux-x86_64/org.sentient.security.policy")
        pol_info.mode = 0o644
        with open(POLKIT_FILE, "rb") as f:
            tar.addfile(pol_info, f)

    print(f"[✔] Tarball created: {tar_path} ({os.path.getsize(tar_path):,} bytes)")

def build_deb():
    deb_path = os.path.join(DIST_DIR, "sentient_1.0.0_amd64.deb")
    print(f"[*] Packaging Debian/Ubuntu package {deb_path}...")

    # 1. debian-binary content
    deb_binary_content = b"2.0\n"

    # 2. Build control.tar.gz
    control_buf = io.BytesIO()
    with tarfile.open(fileobj=control_buf, mode="w:gz") as tar:
        # control file
        control_text = """Package: sentient
Version: 1.0.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Sentient Security <support@sentient.local>
Homepage: https://github.com/Sentient/Sentient
Description: High-Performance Offline Antivirus & Threat Sentinel
 Standalone native binary with hardware-accelerated UI, parallel
 cryptographic threat scanning, pure-Rust YARA engine, Shannon entropy
 analyzer, live process audit, and dual-engine cross-platform architecture.
"""
        c_bytes = control_text.encode("utf-8")
        c_info = tarfile.TarInfo(name="./control")
        c_info.size = len(c_bytes)
        c_info.mtime = int(time.time())
        c_info.mode = 0o644
        c_info.uid = 0
        c_info.gid = 0
        c_info.uname = "root"
        c_info.gname = "root"
        tar.addfile(c_info, io.BytesIO(c_bytes))

        # postinst
        postinst_text = """#!/bin/sh
set -e
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi
exit 0
"""
        p_bytes = postinst_text.encode("utf-8")
        p_info = tarfile.TarInfo(name="./postinst")
        p_info.size = len(p_bytes)
        p_info.mtime = int(time.time())
        p_info.mode = 0o755
        p_info.uid = 0
        p_info.gid = 0
        p_info.uname = "root"
        p_info.gname = "root"
        tar.addfile(p_info, io.BytesIO(p_bytes))

        # prerm
        prerm_text = """#!/bin/sh
set -e
exit 0
"""
        pr_bytes = prerm_text.encode("utf-8")
        pr_info = tarfile.TarInfo(name="./prerm")
        pr_info.size = len(pr_bytes)
        pr_info.mtime = int(time.time())
        pr_info.mode = 0o755
        pr_info.uid = 0
        pr_info.gid = 0
        pr_info.uname = "root"
        pr_info.gname = "root"
        tar.addfile(pr_info, io.BytesIO(pr_bytes))

        # postrm
        postrm_text = """#!/bin/sh
set -e
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi
exit 0
"""
        prm_bytes = postrm_text.encode("utf-8")
        prm_info = tarfile.TarInfo(name="./postrm")
        prm_info.size = len(prm_bytes)
        prm_info.mtime = int(time.time())
        prm_info.mode = 0o755
        prm_info.uid = 0
        prm_info.gid = 0
        prm_info.uname = "root"
        prm_info.gname = "root"
        tar.addfile(prm_info, io.BytesIO(prm_bytes))

    control_tar_gz = control_buf.getvalue()

    # 3. Build data.tar.gz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tar:
        def add_file(src_path, arc_path, mode):
            with open(src_path, "rb") as f:
                content = f.read()
            info = tarfile.TarInfo(name=arc_path)
            info.size = len(content)
            info.mtime = int(time.time())
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            tar.addfile(info, io.BytesIO(content))

        # Binary
        add_file(LINUX_BIN, "./usr/bin/sentient", 0o755)
        # Signatures
        add_file(SIGS_JSON, "./etc/sentient/signatures.json", 0o644)
        add_file(SIGS_JSON, "./usr/share/sentient/signatures.json", 0o644)
        # Desktop
        add_file(DESKTOP_FILE, "./usr/share/applications/sentient.desktop", 0o644)
        # Icons
        add_file(LOGO_PNG, "./usr/share/icons/hicolor/256x256/apps/sentient.png", 0o644)
        add_file(LOGO_PNG, "./usr/share/pixmaps/sentient.png", 0o644)
        # Polkit
        add_file(POLKIT_FILE, "./usr/share/polkit-1/actions/org.sentient.security.policy", 0o644)

    data_tar_gz = data_buf.getvalue()

    # 4. Assemble standard ar archive (format: common debian package ar format)
    # Magic: !<arch>\n
    # File headers: 16 bytes name, 12 bytes mtime, 6 bytes uid, 6 bytes gid, 8 bytes mode, 10 bytes size, 2 bytes `\n
    def ar_header(name, size):
        name_field = f"{name:<16}".encode("ascii")
        mtime_field = f"{int(time.time()):<12}".encode("ascii")
        uid_field = b"0     "
        gid_field = b"0     "
        mode_field = b"100644  "
        size_field = f"{size:<10}".encode("ascii")
        trailer = b"`\n"
        return name_field + mtime_field + uid_field + gid_field + mode_field + size_field + trailer

    with open(deb_path, "wb") as deb:
        deb.write(b"!<arch>\n")

        # 1. debian-binary
        deb.write(ar_header("debian-binary", len(deb_binary_content)))
        deb.write(deb_binary_content)
        if len(deb_binary_content) % 2 != 0:
            deb.write(b"\n")

        # 2. control.tar.gz
        deb.write(ar_header("control.tar.gz", len(control_tar_gz)))
        deb.write(control_tar_gz)
        if len(control_tar_gz) % 2 != 0:
            deb.write(b"\n")

        # 3. data.tar.gz
        deb.write(ar_header("data.tar.gz", len(data_tar_gz)))
        deb.write(data_tar_gz)
        if len(data_tar_gz) % 2 != 0:
            deb.write(b"\n")

    print(f"[✔] Debian package created: {deb_path} ({os.path.getsize(deb_path):,} bytes)")

if __name__ == "__main__":
    build_tarball()
    build_deb()
