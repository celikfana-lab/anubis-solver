// SPDX-License-Identifier: MIT
/*
 * anubis_pci.c — driver for the Anubis proof-of-work card.
 *
 * Binds to the QEMU model (or the real FPGA, same IDs and BAR0 map), maps BAR0,
 * pushes a challenge and a nonce through the register window, starts the
 * search, polls for completion and prints the digest. The card's UART log
 * lines appear on the console because the model writes them, which is how the
 * serial path is exercised in the emulated machine.
 */
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/version.h>
#include "anubis_pci.h"

#define DRV_NAME "anubis_pci"

static int anubis_run(struct pci_dev *pdev, void __iomem *bar,
                      const char *msg, u64 nonce)
{
    size_t len = strlen(msg);
    int words = DIV_ROUND_UP(len, 4);
    int i, t, rc = 0;
    u32 status, lz, id;
    u8 digest[32];
    char hex[65];

    id = readl(bar + ANUBIS_REG_ID);
    dev_info(&pdev->dev, "anubis: BAR0 id=%08x\n", id);
    if (id != ANUBIS_ID) {
        dev_err(&pdev->dev, "anubis: unexpected id %08x\n", id);
        return -ENODEV;
    }

    writel((u32)len, bar + ANUBIS_REG_CH_LEN);
    writel(0, bar + ANUBIS_REG_CH_INDEX);
    for (i = 0; i < words; i++) {
        u32 w = 0;
        size_t n = min_t(size_t, 4, len - 4 * i);
        memcpy(&w, msg + 4 * i, n);
        writel(w, bar + ANUBIS_REG_CH_DATA);
    }
    writel(lower_32_bits(nonce), bar + ANUBIS_REG_NONCE_LO);
    writel(upper_32_bits(nonce), bar + ANUBIS_REG_NONCE_HI);
    dev_info(&pdev->dev, "anubis: start challenge=\"%s\" nonce=%016llx\n",
             msg, nonce);
    writel(ANUBIS_CTRL_START, bar + ANUBIS_REG_CTRL);

    status = 0;
    for (t = 0; t < 500; t++) {
        status = readl(bar + ANUBIS_REG_STATUS);
        if (status & ANUBIS_STATUS_DONE)
            break;
        msleep(1);
    }
    if (!(status & ANUBIS_STATUS_DONE)) {
        dev_err(&pdev->dev, "anubis: timeout, status=%08x\n", status);
        return -ETIMEDOUT;
    }

    lz = (status >> ANUBIS_STATUS_LZ_SHIFT) & ANUBIS_STATUS_LZ_MASK;
    for (i = 0; i < 8; i++) {
        u32 v = readl(bar + ANUBIS_REG_RESULT(i));
        digest[4*i + 0] = v & 0xff;
        digest[4*i + 1] = (v >> 8) & 0xff;
        digest[4*i + 2] = (v >> 16) & 0xff;
        digest[4*i + 3] = (v >> 24) & 0xff;
    }
    bin2hex(hex, digest, 32);
    dev_info(&pdev->dev,
             "anubis: done=1 hit=%d lz=%u digest=%s\n",
             !!(status & ANUBIS_STATUS_HIT), lz, hex);
    return rc;
}

static int anubis_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    void __iomem *bar;
    int rc;

    rc = pcim_enable_device(pdev);
    if (rc)
        return rc;
    rc = pcim_iomap_regions(pdev, BIT(0), DRV_NAME);
    if (rc)
        return rc;

    bar = pcim_iomap_table(pdev)[0];
    if (!bar)
        return -ENOMEM;

    dev_info(&pdev->dev, "anubis: card at %s\n", pci_name(pdev));
    rc = anubis_run(pdev, bar, "hello anubis", 0x0123456789ABCDEFULL);
    dev_info(&pdev->dev, "anubis: self-test %s\n", rc ? "FAILED" : "finished");
    /* a failed self-test still leaves the device bound, so the log is visible */
    return 0;
}

static void anubis_remove(struct pci_dev *pdev)
{
    dev_info(&pdev->dev, "anubis: removed\n");
}

static const struct pci_device_id anubis_ids[] = {
    { PCI_DEVICE(ANUBIS_VENDOR_ID, ANUBIS_DEVICE_ID) },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, anubis_ids);

static struct pci_driver anubis_driver = {
    .name     = DRV_NAME,
    .id_table = anubis_ids,
    .probe    = anubis_probe,
    .remove   = anubis_remove,
};
module_pci_driver(anubis_driver);

MODULE_LICENSE("MIT");
MODULE_DESCRIPTION("Anubis proof-of-work card driver");
