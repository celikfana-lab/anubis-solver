# card/ — the design as a PCIe card, tested under a real kernel

QEMU cannot host Verilog, so this directory tests the **contract** instead: a
QEMU PCI device that implements the same BAR0 register map as
[`chip/rtl/periph/axil_regs.v`](../chip/rtl/periph/axil_regs.v), and a Linux
driver that binds to it. A driver written against this device works unchanged
on the FPGA, because both sides agree on the register map and the PCI IDs.

| file | role |
|---|---|
| `qemu/anubis_pci.c` | QEMU PCI device: BAR0 register file, a real SHA-256 of `challenge \|\| nonce_le` as the algorithm, and the card's UART log lines written to stderr |
| `qemu/anubis_sha256.h` | small SHA-256, test-only |
| `linux/anubis_pci.h` | the BAR0 contract, shared |
| `linux/anubis_pci.c` | driver: probe, map BAR0, push challenge + nonce, start, poll, print the digest |
| `tools/qemu_card_test.sh` | full pipeline: build QEMU with the device, build the driver, make an initramfs, boot a VM, run the self-test, verify |

## Run it

```bash
# once, to stage the root-only kernel image:
sudo cp /boot/vmlinuz-$(uname -r) ~/anubis-qemu/vmlinuz-$(uname -r)
sudo chown $USER: ~/anubis-qemu/vmlinuz-$(uname -r)

./card/tools/qemu_card_test.sh
```

The first run builds QEMU (v8.2.2, x86_64-softmmu only, ~10 minutes on 56
cores); later runs reuse `~/anubis-qemu` and take about ten seconds.

## What it proves

```
=== 7/7 boot the VM
  VM: loading the driver
  [    3.449] anubis_pci 0000:00:03.0: anubis: card at 0000:00:03.0
  [    3.450] anubis_pci 0000:00:03.0: anubis: BAR0 id=a0b15c01
  [    3.450] anubis_pci 0000:00:03.0: anubis: start challenge="hello anubis" nonce=0123456789abcdef
  ANUBIS v1
  DONE NONCE 0x0123456789abcdef LZ 2
  [    3.455] anubis_pci 0000:00:03.0: anubis: done=1 hit=0 lz=2 digest=2793cb96...
  [    3.455] anubis_pci 0000:00:03.0: anubis: self-test finished

=== verify
  expected sha256(challenge||nonce_le) = 2793cb961005ddab986fb8cc103078be7e6ef02acd26623c1a9b601fd0962c44
  card reported                        = 2793cb961005ddab986fb8cc103078be7e6ef02acd26623c1a9b601fd0962c44
RESULT: PASS - driver drove the card and the digest matches
```

So in one run: QEMU enumerates the device, the kernel binds the driver, the
driver drives BAR0 (ID, challenge window, nonce, start, status, results), the
card's UART lines reach the console, and the digest matches `hashlib` on the
host.

## What it does *not* prove

- The algorithm is SHA-256 in the model, not the card's Argon2id/HashX. This is
  a register-protocol test.
- The real FPGA will not necessarily enumerate identically: BAR size, MSI and
  the PCIe hard IP's quirks still need a board.
- No interrupts: the driver polls. A real card would raise an MSI on `done`.

## Notes from building it

- QEMU 8.2 renamed `softmmu_ss` to `system_ss`; the script detects which one the
  tree uses before appending the device to `hw/misc/meson.build`.
- `/boot/vmlinuz-*` is root-only on Ubuntu, so QEMU cannot open it directly —
  the script takes a readable copy.
- `apt-get` on this host exits non-zero because an unrelated `zfs-dkms` fails to
  build; the script checks for the tools it needs instead of trusting apt.
