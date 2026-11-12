/*
 * anubis_pci.c — QEMU PCI device standing in for the FPGA card.
 *
 * Why a C model and not the Verilog: QEMU cannot host RTL, but it can host the
 * *contract*. This device implements the same BAR0 register map as
 * chip/rtl/periph/axil_regs.v, so a Linux driver written against it works
 * unchanged on the real card. The hash is a real SHA-256 of
 * (challenge || nonce little-endian) instead of Argon2id, because the point is
 * the register handshake, not the algorithm.
 *
 * It also prints the card's UART log lines to QEMU's stderr, so the serial
 * console shows what the hardware would have sent.
 *
 * Build: drop into hw/misc/, add to hw/misc/meson.build and hw/misc/Kconfig.
 * See card/README.md.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "qom/object.h"

#include "hw/misc/anubis_pci.h"

#define TYPE_ANUBIS_PCI "anubis-pci"
OBJECT_DECLARE_SIMPLE_TYPE(AnubisPCIState, ANUBIS_PCI)

#include "hw/misc/anubis_sha256.h"

struct AnubisPCIState {
    PCIDevice parent_obj;
    MemoryRegion bar0;
    MemoryRegion mmio;
    QEMUTimer *timer;

    uint32_t ctrl;
    uint32_t status;
    uint32_t nonce_lo, nonce_hi;
    uint32_t ch_len;
    uint32_t ch_idx;
    uint8_t  ch[ANUBIS_CH_BYTES];
    uint8_t  result[32];
    uint8_t  lz;
};

static uint64_t anubis_read(void *opaque, hwaddr addr, unsigned size)
{
    AnubisPCIState *s = opaque;
    uint32_t idx;

    switch (addr) {
    case ANUBIS_REG_ID:        return ANUBIS_ID;
    case ANUBIS_REG_CTRL:      return s->ctrl;
    case ANUBIS_REG_STATUS:
        return (s->status & 0x7) | ((uint32_t)s->lz << ANUBIS_STATUS_LZ_SHIFT);
    case ANUBIS_REG_NONCE_LO:  return s->nonce_lo;
    case ANUBIS_REG_NONCE_HI:  return s->nonce_hi;
    case ANUBIS_REG_CH_LEN:    return s->ch_len;
    case ANUBIS_REG_CH_INDEX:  return s->ch_idx;
    default:
        if (addr >= 0x40 && addr < 0x60) {
            idx = (addr - 0x40) / 4;
            return ((uint32_t)s->result[4*idx + 3] << 24) |
                   ((uint32_t)s->result[4*idx + 2] << 16) |
                   ((uint32_t)s->result[4*idx + 1] << 8)  |
                   ((uint32_t)s->result[4*idx + 0]);
        }
        return 0xDEAD0000;
    }
}

static void anubis_finish(void *opaque)
{
    AnubisPCIState *s = opaque;
    uint8_t buf[ANUBIS_CH_BYTES + 8];
    uint64_t nonce = ((uint64_t)s->nonce_hi << 32) | s->nonce_lo;
    int i, lz = 0;

    memcpy(buf, s->ch, s->ch_len);
    for (i = 0; i < 8; i++)
        buf[s->ch_len + i] = (nonce >> (8 * i)) & 0xFF;
    anubis_sha256(buf, s->ch_len + 8, s->result);

    for (i = 0; i < 32; i++) {
        int b;
        for (b = 7; b >= 0; b--) {
            if ((s->result[i] >> b) & 1) { i = 32; break; }
            lz++;
        }
    }
    s->lz = lz < 255 ? lz : 255;
    /* the stand-in declares a hit when the digest happens to be easy */
    s->status = ANUBIS_STATUS_DONE | (s->lz >= 16 ? ANUBIS_STATUS_HIT : 0);
    fprintf(stderr, "%s NONCE 0x%016" PRIx64 " LZ %d\n",
            (s->status & ANUBIS_STATUS_HIT) ? "HIT" : "DONE", nonce, s->lz);
    fflush(stderr);
}

static void anubis_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    AnubisPCIState *s = opaque;

    switch (addr) {
    case ANUBIS_REG_CTRL:
        s->ctrl = val;
        if (val & ANUBIS_CTRL_START) {
            s->status = ANUBIS_STATUS_BUSY;
            s->ctrl &= ~ANUBIS_CTRL_START;
            fprintf(stderr, "ANUBIS v1\n");
            fflush(stderr);
            /* the card takes some time; 200 us models the hash latency */
            timer_mod(s->timer, qemu_clock_get_us(QEMU_CLOCK_VIRTUAL) + 200);
        }
        break;
    case ANUBIS_REG_NONCE_LO: s->nonce_lo = val; break;
    case ANUBIS_REG_NONCE_HI: s->nonce_hi = val; break;
    case ANUBIS_REG_CH_LEN:
        s->ch_len = val < ANUBIS_CH_BYTES ? val : ANUBIS_CH_BYTES;
        break;
    case ANUBIS_REG_CH_INDEX: s->ch_idx = val; break;
    case ANUBIS_REG_CH_DATA:
        if (s->ch_idx < ANUBIS_CH_BYTES / 4) {
            memcpy(&s->ch[4 * s->ch_idx], &val, 4);
            s->ch_idx++;
        }
        break;
    default:
        break;
    }
}

static const MemoryRegionOps anubis_ops = {
    .read = anubis_read,
    .write = anubis_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
};

static void anubis_realize(PCIDevice *pci, Error **errp)
{
    AnubisPCIState *s = ANUBIS_PCI(pci);

    memory_region_init_io(&s->mmio, OBJECT(s), &anubis_ops, s, "anubis-bar0",
                          ANUBIS_BAR_SIZE);
    pci_register_bar(pci, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
    s->timer = timer_new_us(QEMU_CLOCK_VIRTUAL, anubis_finish, s);
    s->status = 0;
}

static void anubis_exit(PCIDevice *pci)
{
    AnubisPCIState *s = ANUBIS_PCI(pci);
    timer_del(s->timer);
    timer_free(s->timer);
}

static void anubis_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = anubis_realize;
    k->exit = anubis_exit;
    k->vendor_id = ANUBIS_VENDOR_ID;
    k->device_id = ANUBIS_DEVICE_ID;
    k->revision = 1;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo anubis_info = {
    .name          = TYPE_ANUBIS_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AnubisPCIState),
    .class_init    = anubis_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void anubis_register_types(void)
{
    type_register_static(&anubis_info);
}

type_init(anubis_register_types)
