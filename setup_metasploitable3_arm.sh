#!/usr/bin/env bash
#
# setup_metasploitable3_arm.sh
#
# Downloads the Metasploitable3 (ub1404) Vagrant box and converts it
# to a qcow2 disk image that UTM can boot on Apple Silicon Macs.
#
# This does NOT use VirtualBox/Vagrant, since VirtualBox cannot run
# x86 guests on ARM hosts. You still need to manually create the VM
# in UTM and point it at the resulting .qcow2 file (UTM doesn't have
# a scriptable CLI for VM creation).
#
# Usage:
#   chmod +x setup_metasploitable3_arm.sh
#   ./setup_metasploitable3_arm.sh
#
# Optional: pass "win2k8" as an argument to fetch the Windows box instead.
#   ./setup_metasploitable3_arm.sh win2k8

set -euo pipefail

TARGET="${1:-ub1404}"
WORKDIR="$HOME/metasploitable3-arm"
BOX_URL=""
BOX_NAME=""

if [[ "$TARGET" == "ub1404" ]]; then
    BOX_NAME="metasploitable3-ub1404"
elif [[ "$TARGET" == "win2k8" ]]; then
    BOX_NAME="metasploitable3-win2k8"
else
    echo "Unknown target '$TARGET'. Use 'ub1404' or 'win2k8'."
    exit 1
fi

echo "==> Setting up workspace at $WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "==> Checking dependencies (utm, qemu)"
if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required. Install it from https://brew.sh first."
    exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1; then
    echo "Installing qemu (for qemu-img)..."
    brew install qemu
fi

if ! [ -d "/Applications/UTM.app" ]; then
    echo "Installing UTM..."
    brew install --cask utm
fi

echo "==> Fetching current box download URL from Vagrant Cloud for rapid7/${BOX_NAME}"
API_URL="https://app.vagrantup.com/api/v1/box/rapid7/${BOX_NAME}"
BOX_DOWNLOAD_URL=$(curl -s "$API_URL" | python3 -c "
import json,sys
data = json.load(sys.stdin)
versions = data.get('versions', [])
if not versions:
    print('', file=sys.stderr)
    sys.exit(1)
providers = versions[0]['providers']
for p in providers:
    if p['name'] == 'virtualbox':
        print(p['download_url'])
        break
")

if [[ -z "$BOX_DOWNLOAD_URL" ]]; then
    echo "Could not resolve a download URL automatically."
    echo "Go to https://app.vagrantup.com/rapid7/boxes/${BOX_NAME} and download the box manually into $WORKDIR"
    exit 1
fi

BOX_FILE="${BOX_NAME}.box"
if [[ ! -f "$BOX_FILE" ]]; then
    echo "==> Downloading $BOX_FILE (this is several GB, will take a while)"
    curl -L -o "$BOX_FILE" "$BOX_DOWNLOAD_URL"
else
    echo "==> $BOX_FILE already exists, skipping download"
fi

echo "==> Extracting box (it's a gzipped tarball)"
EXTRACT_DIR="${BOX_NAME}-extracted"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$BOX_FILE" -C "$EXTRACT_DIR"

VMDK_FILE=$(find "$EXTRACT_DIR" -name "*.vmdk" | head -n 1)
if [[ -z "$VMDK_FILE" ]]; then
    echo "No .vmdk found inside the box. Check $EXTRACT_DIR manually."
    exit 1
fi

QCOW2_FILE="${WORKDIR}/${BOX_NAME}.qcow2"
echo "==> Converting $VMDK_FILE to qcow2 (compressed)"
qemu-img convert -O qcow2 -c "$VMDK_FILE" "$QCOW2_FILE"

echo ""
echo "==================================================================="
echo "Done. Your bootable disk image is at:"
echo "  $QCOW2_FILE"
echo ""
echo "Next steps (manual, in UTM):"
echo "  1. Open UTM -> Create a New Virtual Machine -> Emulate"
echo "  2. Choose Linux (for ub1404) or Windows (for win2k8) as the OS"
echo "  3. Skip the ISO boot image step"
echo "  4. When asked for storage, remove the default drive and instead"
echo "     import the existing image: $QCOW2_FILE"
echo "  5. Give it at least 2GB RAM / 2 CPU cores"
echo "  6. Set Network mode to 'Shared Network' (keep it off your real LAN)"
echo "  7. Boot it - login is vagrant / vagrant"
echo "==================================================================="
