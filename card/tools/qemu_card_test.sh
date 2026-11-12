#!/bin/bash
# Build QEMU with the anubis-pci device, build the driver, boot a minimal VM and
# run the driver's self-test. Everything below runs unattended.
#
#   ./qemu_card_test.sh            # full pipeline
#   QEMU_SRC=~/qemu ./qemu_card_test.sh --rebuild   # reuse a tree
set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CARD="$(dirname "$HERE")"
REPO="$(dirname "$CARD")"
WORK="${WORK:-$HOME/anubis-qemu}"
QEMU_VER="${QEMU_VER:-v8.2.2}"
SUDO="${SUDO:-sudo}"

say() { printf '\n=== %s\n' "$*"; }
die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

say "1/7 packages"
# apt's exit status is not trusted: an unrelated broken DKMS package (zfs-dkms
# on this host) fails to configure and poisons the whole invocation, so check
# for the tools themselves instead.
# only reach for sudo when something is actually missing
NEED_PKGS=0
for t in meson ninja gcc git cpio pkg-config; do
    command -v "$t" >/dev/null || NEED_PKGS=1
done
pkg-config --exists glib-2.0   || NEED_PKGS=1
pkg-config --exists pixman-1   || NEED_PKGS=1
[ -x /bin/busybox ]            || NEED_PKGS=1
[ -d "/lib/modules/$(uname -r)/build" ] || NEED_PKGS=1
if [ "$NEED_PKGS" = 1 ]; then
    $SUDO apt-get install -y --no-install-recommends \
        build-essential ninja-build meson pkg-config python3-venv \
        libglib2.0-dev libpixman-1-dev libfdt-dev zlib1g-dev \
        git busybox-static cpio bc flex bison \
        "linux-headers-$(uname -r)" >/dev/null 2>&1 || true
fi
for t in meson ninja gcc git cpio pkg-config; do
    command -v "$t" >/dev/null || die "missing $t"
done
pkg-config --exists glib-2.0 || die "glib headers missing"
pkg-config --exists pixman-1  || die "pixman headers missing"
[ -x /bin/busybox ] || die "busybox missing"
[ -d "/lib/modules/$(uname -r)/build" ] || die "kernel headers missing"
echo "  tools, glib, pixman, busybox and kernel headers present"

mkdir -p "$WORK"

say "2/7 QEMU source ($QEMU_VER)"
if [ ! -d "$WORK/qemu" ]; then
    git clone --depth 1 -b "$QEMU_VER" \
        https://gitlab.com/qemu-project/qemu.git "$WORK/qemu" \
        >/dev/null 2>&1 || die "git clone"
fi

say "3/7 add the device model"
cp "$CARD/qemu/anubis_pci.c"        "$WORK/qemu/hw/misc/anubis_pci.c"
cp "$CARD/qemu/anubis_sha256.h"     "$WORK/qemu/include/hw/misc/anubis_sha256.h"
cp "$CARD/linux/anubis_pci.h"       "$WORK/qemu/include/hw/misc/anubis_pci.h"
# QEMU 7.2+ calls the variable system_ss, older trees softmmu_ss
if grep -q softmmu_ss "$WORK/qemu/hw/misc/meson.build"; then
    MSS=softmmu_ss
else
    MSS=system_ss
fi
grep -q anubis_pci "$WORK/qemu/hw/misc/meson.build" || \
    printf "\n%s.add(when: 'CONFIG_ANUBIS_PCI', if_true: files('anubis_pci.c'))\n" "$MSS" \
        >> "$WORK/qemu/hw/misc/meson.build"
echo "  device added to $MSS"
grep -q ANUBIS_PCI "$WORK/qemu/hw/misc/Kconfig" || \
    printf "\nconfig ANUBIS_PCI\n    bool\n    default y\n    depends on PCI\n" \
        >> "$WORK/qemu/hw/misc/Kconfig"

say "4/7 build qemu-system-x86_64"
if [ ! -f "$WORK/qemu/build/build.ninja" ]; then
    ( cd "$WORK/qemu" && ./configure --target-list=x86_64-softmmu \
        --disable-docs --disable-tools --disable-guest-agent \
        --disable-werror > "$WORK/configure.log" 2>&1 ) || {
            tail -15 "$WORK/configure.log"; die "configure"; }
fi
# always make: it is incremental, and the device source changes between runs
( cd "$WORK/qemu" && make -j"$(nproc)" > "$WORK/make.log" 2>&1 ) || {
        tail -20 "$WORK/make.log"; die "qemu build"; }
QEMU="$WORK/qemu/build/qemu-system-x86_64"
"$QEMU" -device help 2>/dev/null | grep -q anubis-pci || die "device missing from QEMU"

say "5/7 build the driver"
KVER="$(uname -r)"
make -C "/lib/modules/$KVER/build" M="$CARD/linux" modules >/dev/null 2>&1 \
    || die "module build"

say "6/7 initramfs"
IRD="$WORK/initrd"
rm -rf "$IRD"; mkdir -p "$IRD"/{bin,proc,sys,dev}
cp /bin/busybox "$IRD/bin/"
for a in sh mount insmod poweroff dmesg; do ln -sf busybox "$IRD/bin/$a"; done
cp "$CARD/linux/anubis_pci.ko" "$IRD/"
cat > "$IRD/init" <<INIT
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
echo "VM: loading the driver"
insmod /anubis_pci.ko || echo "VM: insmod failed"
sleep 1
echo "VM: dmesg tail"
dmesg | grep -i anubis | tail -20
poweroff -f
INIT
chmod +x "$IRD/init"
( cd "$IRD" && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$WORK/initrd.cpio.gz" \
    || die "initramfs"

say "7/7 boot the VM"
# /boot/vmlinuz-* is root-only on this distro, so take a readable copy
KIMG="$WORK/vmlinuz-$KVER"
if [ ! -r "$KIMG" ]; then
    # pre-stage it (root-only file):  sudo cp /boot/vmlinuz-$KVER $KIMG
    die "kernel image $KIMG missing; stage it with sudo cp"
fi
LOG="$WORK/qemu.log"
timeout 180 "$QEMU" -M q35 -m 512 -smp 1 -no-reboot \
    -kernel "$KIMG" -initrd "$WORK/initrd.cpio.gz" \
    -append "console=ttyS0 rdinit=/init loglevel=7" \
    -nographic -device anubis-pci > "$LOG" 2>&1
echo "--- console ---"
grep -E "VM:|anubis|ANUBIS|HIT" "$LOG" | sed 's/^/  /'

say "verify"
EXPECT="$(python3 - "$CARD" <<'PY'
import hashlib, struct
msg = b"hello anubis"
nonce = 0x0123456789ABCDEF
print(hashlib.sha256(msg + nonce.to_bytes(8, "little")).hexdigest())
PY
)"
GOT="$(grep -o 'digest=[0-9a-f]*' "$LOG" | head -1 | cut -d= -f2)"
echo "  expected sha256(challenge||nonce_le) = $EXPECT"
echo "  card reported                        = ${GOT:-<none>}"
if [ -n "$GOT" ] && [ "$GOT" = "$EXPECT" ]; then
    echo "RESULT: PASS - driver drove the card and the digest matches"
else
    echo "RESULT: FAIL"
    exit 1
fi
