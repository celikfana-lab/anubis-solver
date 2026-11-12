/*
 * levelzero_argon2.c — oneAPI Level Zero Argon2id backend.
 *
 * One work-group (64 work-items) per candidate nonce; the 1 KiB Argon2 block
 * is in local memory, the 19 MiB matrix in device memory. Mirrors the CUDA
 * backend; enabled with ANUBIS_GPU_ARGON2=1 and re-verified on the CPU.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <level_zero/ze_api.h>

#include "argon2id_l0.spv.h"

#define A2_M 19456u
#define A2_L0_LANES 64u

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} a2_results;

typedef ze_result_t (*fn_zeInit)(ze_init_flags_t);
typedef ze_result_t (*fn_zeDriverGet)(uint32_t *, ze_driver_handle_t *);
typedef ze_result_t (*fn_zeDeviceGet)(ze_driver_handle_t, uint32_t *,
                                      ze_device_handle_t *);
typedef ze_result_t (*fn_zeDeviceGetProperties)(ze_device_handle_t,
                                                ze_device_properties_t *);
typedef ze_result_t (*fn_zeDeviceGetCmdQueueGroupProperties)(
    ze_device_handle_t, uint32_t *, ze_command_queue_group_properties_t *);
typedef ze_result_t (*fn_zeContextCreate)(ze_driver_handle_t,
                                          const ze_context_desc_t *,
                                          ze_context_handle_t *);
typedef ze_result_t (*fn_zeCommandQueueCreate)(ze_context_handle_t,
                                               ze_device_handle_t,
                                               const ze_command_queue_desc_t *,
                                               ze_command_queue_handle_t *);
typedef ze_result_t (*fn_zeCommandListCreate)(ze_context_handle_t,
                                              ze_device_handle_t,
                                              const ze_command_list_desc_t *,
                                              ze_command_list_handle_t *);
typedef ze_result_t (*fn_zeCommandListClose)(ze_command_list_handle_t);
typedef ze_result_t (*fn_zeCommandListReset)(ze_command_list_handle_t);
typedef ze_result_t (*fn_zeExecute)(ze_command_queue_handle_t, uint32_t,
                                    ze_command_list_handle_t *,
                                    ze_fence_handle_t);
typedef ze_result_t (*fn_zeSynchronize)(ze_command_queue_handle_t, uint64_t);
typedef ze_result_t (*fn_zeModuleCreate)(ze_context_handle_t,
                                         ze_device_handle_t,
                                         const ze_module_desc_t *,
                                         ze_module_handle_t *,
                                         ze_module_build_log_handle_t *);
typedef ze_result_t (*fn_zeKernelCreate)(ze_module_handle_t,
                                         const ze_kernel_desc_t *,
                                         ze_kernel_handle_t *);
typedef ze_result_t (*fn_zeKernelSetArg)(ze_kernel_handle_t, uint32_t, size_t,
                                         const void *);
typedef ze_result_t (*fn_zeKernelSetGroupSize)(ze_kernel_handle_t, uint32_t,
                                               uint32_t, uint32_t);
typedef ze_result_t (*fn_zeMemAllocShared)(ze_context_handle_t,
                                           const ze_device_mem_alloc_desc_t *,
                                           const ze_host_mem_alloc_desc_t *,
                                           size_t, size_t, ze_device_handle_t,
                                           void **);
typedef ze_result_t (*fn_zeMemAllocDevice)(ze_context_handle_t,
                                           const ze_device_mem_alloc_desc_t *,
                                           size_t, size_t, ze_device_handle_t,
                                           void **);
typedef ze_result_t (*fn_zeLaunch)(ze_command_list_handle_t,
                                   ze_kernel_handle_t,
                                   const ze_group_count_t *, ze_event_handle_t,
                                   uint32_t, ze_event_handle_t *);

static struct {
    int inited;
    int available;
    pthread_mutex_t mu;
    ze_context_handle_t ctx;
    ze_device_handle_t dev;
    ze_command_queue_handle_t queue;
    ze_command_list_handle_t list;
    ze_module_handle_t module;
    ze_kernel_handle_t kernel;
    ze_kernel_handle_t kernel_b2;
    ze_kernel_handle_t kernel_dbg;
    ze_kernel_handle_t kernel_fill;
    void *fillbuf;
    void *fillargs;
    void *challenge;
    void *b2out;
    a2_results *results;
    uint64_t *mem;
    char info[160];
} g_a2 = { 0, 0, PTHREAD_MUTEX_INITIALIZER, NULL, NULL, NULL, NULL, NULL,
           NULL, NULL, NULL, NULL, {0} };

static fn_zeInit p_zeInit;
static fn_zeDriverGet p_zeDriverGet;
static fn_zeDeviceGet p_zeDeviceGet;
static fn_zeDeviceGetProperties p_zeDeviceGetProperties;
static fn_zeDeviceGetCmdQueueGroupProperties p_zeDeviceGetQueueGroups;
static fn_zeContextCreate p_zeContextCreate;
static fn_zeCommandQueueCreate p_zeCommandQueueCreate;
static fn_zeCommandListCreate p_zeCommandListCreate;
static fn_zeCommandListClose p_zeCommandListClose;
static fn_zeCommandListReset p_zeCommandListReset;
static fn_zeExecute p_zeExecute;
static fn_zeSynchronize p_zeSynchronize;
static fn_zeModuleCreate p_zeModuleCreate;
static fn_zeKernelCreate p_zeKernelCreate;
static fn_zeKernelSetArg p_zeKernelSetArg;
static fn_zeKernelSetGroupSize p_zeKernelSetGroupSize;
static fn_zeMemAllocShared p_zeMemAllocShared;
static fn_zeMemAllocDevice p_zeMemAllocDevice;
static fn_zeLaunch p_zeLaunch;

static double a2_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t a2_env_u32(const char *name, uint32_t def) {
    const char *s = getenv(name);
    if (s != NULL && *s != '\0') {
        return (uint32_t)strtoul(s, NULL, 0);
    }
    return def;
}

static int load_syms(void *h) {
#define SYM(field, name)                                                     \
    do {                                                                     \
        field = (void *)dlsym(h, name);                                      \
        if (field == NULL) {                                                 \
            return 0;                                                        \
        }                                                                    \
    } while (0)
    SYM(p_zeInit, "zeInit");
    SYM(p_zeDriverGet, "zeDriverGet");
    SYM(p_zeDeviceGet, "zeDeviceGet");
    SYM(p_zeDeviceGetProperties, "zeDeviceGetProperties");
    SYM(p_zeDeviceGetQueueGroups, "zeDeviceGetCommandQueueGroupProperties");
    SYM(p_zeContextCreate, "zeContextCreate");
    SYM(p_zeCommandQueueCreate, "zeCommandQueueCreate");
    SYM(p_zeCommandListCreate, "zeCommandListCreate");
    SYM(p_zeCommandListClose, "zeCommandListClose");
    SYM(p_zeCommandListReset, "zeCommandListReset");
    SYM(p_zeExecute, "zeCommandQueueExecuteCommandLists");
    SYM(p_zeSynchronize, "zeCommandQueueSynchronize");
    SYM(p_zeModuleCreate, "zeModuleCreate");
    SYM(p_zeKernelCreate, "zeKernelCreate");
    SYM(p_zeKernelSetArg, "zeKernelSetArgumentValue");
    SYM(p_zeKernelSetGroupSize, "zeKernelSetGroupSize");
    SYM(p_zeMemAllocShared, "zeMemAllocShared");
    SYM(p_zeMemAllocDevice, "zeMemAllocDevice");
    SYM(p_zeLaunch, "zeCommandListAppendLaunchKernel");
#undef SYM
    return 1;
}

static int l0_a2_init(void) {
    void *h;
    uint32_t ndrv = 0, ndev = 0, ngroups = 0, ordinal = 0;
    int have_ordinal = 0;
    ze_driver_handle_t drv[8];
    ze_device_handle_t dev[8];
    ze_device_properties_t props;
    ze_command_queue_group_properties_t groups[8];
    ze_context_desc_t cdesc;
    ze_command_queue_desc_t qdesc;
    ze_command_list_desc_t ldesc;
    ze_module_desc_t mdesc;
    ze_kernel_desc_t kdesc;
    ze_device_mem_alloc_desc_t ddesc;
    ze_host_mem_alloc_desc_t hdesc;
    size_t mem_bytes = (size_t)A2_L0_LANES * (size_t)(A2_M + 3u) * 1024u;

    if (g_a2.inited) {
        return g_a2.available;
    }
    g_a2.inited = 1;
    {
        const char *off = getenv("ANUBIS_NO_LEVELZERO");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            return 0;
        }
    }
    h = dlopen("libze_loader.so.1", RTLD_NOW | RTLD_LOCAL);
    if (h == NULL || !load_syms(h)) {
        return 0;
    }
    if (p_zeInit(0) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeDriverGet(&ndrv, NULL) != ZE_RESULT_SUCCESS || ndrv == 0) {
        return 0;
    }
    if (ndrv > 8) {
        ndrv = 8;
    }
    if (p_zeDriverGet(&ndrv, drv) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeDeviceGet(drv[0], &ndev, NULL) != ZE_RESULT_SUCCESS || ndev == 0) {
        return 0;
    }
    if (ndev > 8) {
        ndev = 8;
    }
    if (p_zeDeviceGet(drv[0], &ndev, dev) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    g_a2.dev = dev[0];
    memset(&props, 0, sizeof(props));
    props.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
    if (p_zeDeviceGetProperties(g_a2.dev, &props) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeDeviceGetQueueGroups(g_a2.dev, &ngroups, NULL) != ZE_RESULT_SUCCESS ||
        ngroups == 0) {
        return 0;
    }
    if (ngroups > 8) {
        ngroups = 8;
    }
    if (p_zeDeviceGetQueueGroups(g_a2.dev, &ngroups, groups) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    for (uint32_t i = 0; i < ngroups; i++) {
        if ((groups[i].flags & ZE_COMMAND_QUEUE_GROUP_PROPERTY_FLAG_COMPUTE) !=
            0) {
            ordinal = i;
            have_ordinal = 1;
            break;
        }
    }
    if (!have_ordinal) {
        return 0;
    }
    memset(&cdesc, 0, sizeof(cdesc));
    cdesc.stype = ZE_STRUCTURE_TYPE_CONTEXT_DESC;
    if (p_zeContextCreate(drv[0], &cdesc, &g_a2.ctx) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&qdesc, 0, sizeof(qdesc));
    qdesc.stype = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC;
    qdesc.ordinal = ordinal;
    qdesc.index = 0;
    qdesc.mode = ZE_COMMAND_QUEUE_MODE_DEFAULT;
    qdesc.priority = ZE_COMMAND_QUEUE_PRIORITY_NORMAL;
    if (p_zeCommandQueueCreate(g_a2.ctx, g_a2.dev, &qdesc, &g_a2.queue) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&ldesc, 0, sizeof(ldesc));
    ldesc.stype = ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC;
    ldesc.commandQueueGroupOrdinal = ordinal;
    if (p_zeCommandListCreate(g_a2.ctx, g_a2.dev, &ldesc, &g_a2.list) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&mdesc, 0, sizeof(mdesc));
    mdesc.stype = ZE_STRUCTURE_TYPE_MODULE_DESC;
    mdesc.format = ZE_MODULE_FORMAT_IL_SPIRV;
    mdesc.inputSize = argon2id_l0_spv_bytes;
    mdesc.pInputModule = (const uint8_t *)argon2id_l0_spv;
    if (p_zeModuleCreate(g_a2.ctx, g_a2.dev, &mdesc, &g_a2.module, NULL) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&kdesc, 0, sizeof(kdesc));
    kdesc.stype = ZE_STRUCTURE_TYPE_KERNEL_DESC;
    kdesc.pKernelName = "argon2id_pow";
    if (p_zeKernelCreate(g_a2.module, &kdesc, &g_a2.kernel) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeKernelSetGroupSize(g_a2.kernel, 32, 1, 1) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    kdesc.pKernelName = "b2_test";
    if (p_zeKernelCreate(g_a2.module, &kdesc, &g_a2.kernel_b2) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeKernelSetGroupSize(g_a2.kernel_b2, 32, 1, 1) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    kdesc.pKernelName = "a2_dbg";
    if (p_zeKernelCreate(g_a2.module, &kdesc, &g_a2.kernel_dbg) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeKernelSetGroupSize(g_a2.kernel_dbg, 32, 1, 1) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    kdesc.pKernelName = "fill_dbg";
    if (p_zeKernelCreate(g_a2.module, &kdesc, &g_a2.kernel_fill) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeKernelSetGroupSize(g_a2.kernel_fill, 32, 1, 1) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&ddesc, 0, sizeof(ddesc));
    ddesc.stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC;
    memset(&hdesc, 0, sizeof(hdesc));
    hdesc.stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC;
    if (p_zeMemAllocShared(g_a2.ctx, &ddesc, &hdesc, 4096, 64, g_a2.dev,
                           &g_a2.challenge) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeMemAllocShared(g_a2.ctx, &ddesc, &hdesc, sizeof(a2_results), 64,
                           g_a2.dev, (void **)&g_a2.results) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeMemAllocShared(g_a2.ctx, &ddesc, &hdesc, 256, 64, g_a2.dev,
                           &g_a2.b2out) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeMemAllocShared(g_a2.ctx, &ddesc, &hdesc, 3u * 128u * 8u, 64,
                           g_a2.dev, &g_a2.fillbuf) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeMemAllocShared(g_a2.ctx, &ddesc, &hdesc, 16, 64, g_a2.dev,
                           &g_a2.fillargs) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeMemAllocDevice(g_a2.ctx, &ddesc, mem_bytes, 64, g_a2.dev,
                           (void **)&g_a2.mem) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    snprintf(g_a2.info, sizeof(g_a2.info), "Level Zero Argon2id: %.80s",
             props.name);
    g_a2.available = 1;
    return 1;
}

int anubis_l0_argon2_available(void) {
    return l0_a2_init();
}

const char *anubis_l0_argon2_info(void) {
    if (!l0_a2_init()) {
        return NULL;
    }
    return g_a2.info;
}

static int a2_dispatch(uint32_t clen, uint32_t use_le, uint32_t difficulty,
                       uint32_t base, uint32_t count) {
    ze_group_count_t gc;
    void *challenge = g_a2.challenge;
    void *mem = g_a2.mem;
    void *res = g_a2.results;

    if (p_zeKernelSetArg(g_a2.kernel, 0, sizeof(void *), &challenge) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 1, sizeof(uint32_t), &clen) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 2, sizeof(uint32_t), &use_le) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 3, sizeof(uint32_t), &difficulty) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 4, sizeof(uint32_t), &base) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 5, sizeof(uint32_t), &count) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 6, sizeof(void *), &mem) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel, 7, sizeof(void *), &res) !=
            ZE_RESULT_SUCCESS) {
        return -1;
    }
    g_a2.results->count = 0;
    gc.groupCountX = count;
    gc.groupCountY = 1;
    gc.groupCountZ = 1;
    if (p_zeCommandListReset(g_a2.list) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeLaunch(g_a2.list, g_a2.kernel, &gc, NULL, 0, NULL) !=
        ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeCommandListClose(g_a2.list) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeExecute(g_a2.queue, 1, &g_a2.list, NULL) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeSynchronize(g_a2.queue, UINT64_MAX) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    return 0;
}

static void a2_hex(const uint32_t w[8], char out[65]) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned v = (w[i] >> (8 * (3 - j))) & 0xFFu;
            out[(4 * i + j) * 2 + 0] = hexd[v >> 4];
            out[(4 * i + j) * 2 + 1] = hexd[v & 0xFu];
        }
    }
    out[64] = '\0';
}

/*
 * Returns 0 on a hit (caller re-verifies), 1 if the range was exhausted,
 * -1 on backend failure.
 */
int anubis_l0_argon2_solve(const uint8_t *challenge, size_t clen, int use_le,
                           int difficulty, uint64_t max_nonce, double budget_ms,
                           uint32_t *out_nonce, char out_hex[65],
                           double *out_ms) {
    uint32_t lanes;
    uint64_t base = 0;
    uint64_t maxn;
    double t0;
    int rc = 1;

    if (challenge == NULL || out_nonce == NULL || out_hex == NULL ||
        clen > 4096) {
        return -1;
    }
    if (!l0_a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    t0 = a2_now();
    lanes = a2_env_u32("ANUBIS_L0_ARGON2_LANES", A2_L0_LANES);
    if (lanes < 1u) {
        lanes = 1u;
    }
    if (lanes > A2_L0_LANES) {
        lanes = A2_L0_LANES;
    }
    memcpy(g_a2.challenge, challenge, clen);
    maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;

    while (base <= maxn) {
        uint64_t remaining = maxn - base + 1;
        uint32_t count = (uint32_t)(remaining < (uint64_t)lanes
                                        ? remaining
                                        : (uint64_t)lanes);
        if (count == 0) {
            break;
        }
        if (a2_dispatch((uint32_t)clen, (uint32_t)use_le, (uint32_t)difficulty,
                        (uint32_t)base, count) != 0) {
            rc = -1;
            break;
        }
        if (g_a2.results->count > 0) {
            uint32_t best = g_a2.results->nonces[0];
            uint32_t bh[8];
            memcpy(bh, g_a2.results->hashes[0], sizeof(bh));
            a2_hex(bh, out_hex);
            *out_nonce = best;
            if (out_ms != NULL) {
                *out_ms = (a2_now() - t0) * 1000.0;
            }
            rc = 0;
            break;
        }
        base += count;
        if (budget_ms > 0.0 && (a2_now() - t0) * 1000.0 > budget_ms) {
            rc = 1;
            break;
        }
    }

    pthread_mutex_unlock(&g_a2.mu);
    return rc;
}

/* Compute the Argon2id digest for one nonce (testing/debug helper). */
int anubis_l0_argon2_digest(const uint8_t *challenge, size_t clen, int use_le,
                            uint32_t nonce, uint8_t out[32]) {
    uint32_t bh[8];

    if (challenge == NULL || out == NULL || clen > 4096 || !l0_a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    memcpy(g_a2.challenge, challenge, clen);
    if (a2_dispatch((uint32_t)clen, (uint32_t)use_le, 0u, nonce, 1u) != 0 ||
        g_a2.results->count == 0) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    memcpy(bh, g_a2.results->hashes[0], sizeof(bh));
    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(bh[i] >> 24);
        out[4 * i + 1] = (uint8_t)(bh[i] >> 16);
        out[4 * i + 2] = (uint8_t)(bh[i] >> 8);
        out[4 * i + 3] = (uint8_t)bh[i];
    }
    pthread_mutex_unlock(&g_a2.mu);
    return 0;
}

int anubis_l0_b2_test(const uint8_t *in, size_t len, size_t outlen,
                      uint8_t *out) {
    void *inp;
    void *outp;
    uint32_t len32 = (uint32_t)len;
    uint32_t out32 = (uint32_t)outlen;
    ze_group_count_t gc = {1, 1, 1};

    if (in == NULL || out == NULL || len > 4096 || outlen > 64 ||
        !l0_a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    memcpy(g_a2.challenge, in, len);
    inp = g_a2.challenge;
    outp = g_a2.b2out;
    if (p_zeKernelSetArg(g_a2.kernel_b2, 0, sizeof(void *), &inp) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_b2, 1, sizeof(uint32_t), &len32) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_b2, 2, sizeof(uint32_t), &out32) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_b2, 3, sizeof(void *), &outp) !=
            ZE_RESULT_SUCCESS ||
        p_zeCommandListReset(g_a2.list) != ZE_RESULT_SUCCESS ||
        p_zeLaunch(g_a2.list, g_a2.kernel_b2, &gc, NULL, 0, NULL) !=
            ZE_RESULT_SUCCESS ||
        p_zeCommandListClose(g_a2.list) != ZE_RESULT_SUCCESS ||
        p_zeExecute(g_a2.queue, 1, &g_a2.list, NULL) != ZE_RESULT_SUCCESS ||
        p_zeSynchronize(g_a2.queue, UINT64_MAX) != ZE_RESULT_SUCCESS) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    memcpy(out, g_a2.b2out, outlen);
    pthread_mutex_unlock(&g_a2.mu);
    return 0;
}

int anubis_l0_a2_dbg(const uint8_t *challenge, size_t clen, int use_le,
                     uint32_t nonce, uint8_t out[99]) {
    void *inp;
    void *outp;
    uint32_t clen32 = (uint32_t)clen;
    uint32_t ule = (uint32_t)use_le;
    ze_group_count_t gc = {1, 1, 1};

    if (challenge == NULL || out == NULL || clen > 4096 || !l0_a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    memcpy(g_a2.challenge, challenge, clen);
    inp = g_a2.challenge;
    outp = g_a2.b2out;
    if (p_zeKernelSetArg(g_a2.kernel_dbg, 0, sizeof(void *), &inp) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_dbg, 1, sizeof(uint32_t), &clen32) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_dbg, 2, sizeof(uint32_t), &ule) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_dbg, 3, sizeof(uint32_t), &nonce) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_dbg, 4, sizeof(void *), &outp) !=
            ZE_RESULT_SUCCESS ||
        p_zeCommandListReset(g_a2.list) != ZE_RESULT_SUCCESS ||
        p_zeLaunch(g_a2.list, g_a2.kernel_dbg, &gc, NULL, 0, NULL) !=
            ZE_RESULT_SUCCESS ||
        p_zeCommandListClose(g_a2.list) != ZE_RESULT_SUCCESS ||
        p_zeExecute(g_a2.queue, 1, &g_a2.list, NULL) != ZE_RESULT_SUCCESS ||
        p_zeSynchronize(g_a2.queue, UINT64_MAX) != ZE_RESULT_SUCCESS) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    memcpy(out, g_a2.b2out, 99);
    pthread_mutex_unlock(&g_a2.mu);
    return 0;
}

int anubis_l0_fill_test(uint64_t prev[128], uint64_t ref[128], uint64_t out[128],
                        int with_xor) {
    void *mem = g_a2.fillbuf;
    void *args = g_a2.fillargs;
    uint32_t a[4];
    ze_group_count_t gc = {1, 1, 1};

    if (!l0_a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    memcpy((uint8_t *)mem, prev, 128 * 8);
    memcpy((uint8_t *)mem + 1024, ref, 128 * 8);
    memset((uint8_t *)mem + 2048, 0, 1024);
    a[0] = 2;
    a[1] = 0;
    a[2] = 1;
    a[3] = (uint32_t)(with_xor ? 1 : 0);
    memcpy(args, a, sizeof(a));
    if (p_zeKernelSetArg(g_a2.kernel_fill, 0, sizeof(void *), &mem) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_a2.kernel_fill, 1, sizeof(void *), &args) !=
            ZE_RESULT_SUCCESS ||
        p_zeCommandListReset(g_a2.list) != ZE_RESULT_SUCCESS ||
        p_zeLaunch(g_a2.list, g_a2.kernel_fill, &gc, NULL, 0, NULL) !=
            ZE_RESULT_SUCCESS ||
        p_zeCommandListClose(g_a2.list) != ZE_RESULT_SUCCESS ||
        p_zeExecute(g_a2.queue, 1, &g_a2.list, NULL) != ZE_RESULT_SUCCESS ||
        p_zeSynchronize(g_a2.queue, UINT64_MAX) != ZE_RESULT_SUCCESS) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    memcpy(out, (uint8_t *)mem + 2048, 1024);
    pthread_mutex_unlock(&g_a2.mu);
    return 0;
}
/* Dump the first 32 words of the last block (testing/debug helper). */
int anubis_l0_a2_lastblock(const uint8_t *challenge, size_t clen, int use_le,
                           uint32_t nonce, uint64_t out[32]) {
    if (challenge == NULL || out == NULL || clen > 4096 || !l0_a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    memcpy(g_a2.challenge, challenge, clen);
    if (a2_dispatch((uint32_t)clen, (uint32_t)use_le, 0xFFFFFFFEu, nonce,
                    1u) != 0 ||
        g_a2.results->count == 0) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    {
        const uint32_t *flat = (const uint32_t *)g_a2.results->hashes;
        for (int i = 0; i < 32; i++) {
            out[i] = (uint64_t)flat[2 * i] | ((uint64_t)flat[2 * i + 1] << 32);
        }
    }
    pthread_mutex_unlock(&g_a2.mu);
    return 0;
}
