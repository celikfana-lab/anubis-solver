/* anubis_pci.h — the BAR0 contract, shared by the driver and the QEMU model.
 *
 * Mirrors beyond/rtl/periph/axil_regs.v. Vendor/device are whatever you wire into
 * the FPGA; these values match the QEMU device so the same driver talks to both.
 */
#ifndef ANUBIS_PCI_H
#define ANUBIS_PCI_H

#define ANUBIS_VENDOR_ID  0x1B36
#define ANUBIS_DEVICE_ID  0x0A0B

#define ANUBIS_BAR_SIZE   0x100

/* register offsets, 32-bit each, little-endian */
#define ANUBIS_REG_ID           0x00
#define ANUBIS_REG_CTRL         0x04
#define ANUBIS_REG_STATUS       0x08
#define ANUBIS_REG_NONCE_LO     0x0C
#define ANUBIS_REG_NONCE_HI     0x10
#define ANUBIS_REG_CH_LEN       0x14
#define ANUBIS_REG_CH_DATA      0x18   /* write word at CH_INDEX, then CH_INDEX++ */
#define ANUBIS_REG_CH_INDEX     0x1C
#define ANUBIS_REG_RESULT(i)    (0x40 + 4 * (i))   /* 8 words, 32-byte digest */

#define ANUBIS_ID               0xA0B15C01

#define ANUBIS_CTRL_START       0x1
#define ANUBIS_CTRL_ABORT       0x2
#define ANUBIS_CTRL_ALGO_SHIFT  2
#define ANUBIS_CTRL_ALGO_MASK   0x3

#define ANUBIS_STATUS_BUSY      0x1
#define ANUBIS_STATUS_DONE      (1 << 1)
#define ANUBIS_STATUS_HIT       (1 << 2)
#define ANUBIS_STATUS_LZ_SHIFT  8
#define ANUBIS_STATUS_LZ_MASK   0xFF

/* the challenge window: 256 bytes through a 4-byte register */
#define ANUBIS_CH_BYTES         256

#endif
