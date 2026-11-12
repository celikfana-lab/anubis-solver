/*
 * levelzero_hashx.c — oneAPI Level Zero backend for Anubis HashX.
 *
 * The HashX program is uploaded once; each work-item interprets it for one
 * nonce. Enabled with ANUBIS_GPU_HASHX=1; hits are re-verified on the CPU.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <level_zero/ze_api.h>

#include "hashx_l0.spv.h"
#include "hashx.h"

#define HX_MAX_INSTR 512
#define HX_WG 256u
#define HX_CHUNK (1u << 22)

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} hx_results;

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
    uint32_t *prog;
    hx_results *results;
    char info[160];
} g_hx = { 0, 0, PTHREAD_MUTEX_INITIALIZER, NULL, NULL, NULL, NULL, NULL,
           NULL, NULL, NULL, {0} };

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

static double hx_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t hx_env_u32(const char *name, uint32_t def) {
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

static int hx_init(void) {
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

    if (g_hx.inited) {
        return g_hx.available;
    }
    g_hx.inited = 1;
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
    g_hx.dev = dev[0];
    memset(&props, 0, sizeof(props));
    props.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
    if (p_zeDeviceGetProperties(g_hx.dev, &props) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeDeviceGetQueueGroups(g_hx.dev, &ngroups, NULL) != ZE_RESULT_SUCCESS ||
        ngroups == 0) {
        return 0;
    }
    if (ngroups > 8) {
        ngroups = 8;
    }
    if (p_zeDeviceGetQueueGroups(g_hx.dev, &ngroups, groups) !=
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
    if (p_zeContextCreate(drv[0], &cdesc, &g_hx.ctx) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&qdesc, 0, sizeof(qdesc));
    qdesc.stype = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC;
    qdesc.ordinal = ordinal;
    qdesc.index = 0;
    qdesc.mode = ZE_COMMAND_QUEUE_MODE_DEFAULT;
    qdesc.priority = ZE_COMMAND_QUEUE_PRIORITY_NORMAL;
    if (p_zeCommandQueueCreate(g_hx.ctx, g_hx.dev, &qdesc, &g_hx.queue) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&ldesc, 0, sizeof(ldesc));
    ldesc.stype = ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC;
    ldesc.commandQueueGroupOrdinal = ordinal;
    if (p_zeCommandListCreate(g_hx.ctx, g_hx.dev, &ldesc, &g_hx.list) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&mdesc, 0, sizeof(mdesc));
    mdesc.stype = ZE_STRUCTURE_TYPE_MODULE_DESC;
    mdesc.format = ZE_MODULE_FORMAT_IL_SPIRV;
    mdesc.inputSize = hashx_l0_spv_bytes;
    mdesc.pInputModule = (const uint8_t *)hashx_l0_spv;
    if (p_zeModuleCreate(g_hx.ctx, g_hx.dev, &mdesc, &g_hx.module, NULL) !=
        ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&kdesc, 0, sizeof(kdesc));
    kdesc.stype = ZE_STRUCTURE_TYPE_KERNEL_DESC;
    kdesc.pKernelName = "hashx_pow";
    if (p_zeKernelCreate(g_hx.module, &kdesc, &g_hx.kernel) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeKernelSetGroupSize(g_hx.kernel, HX_WG, 1, 1) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    memset(&ddesc, 0, sizeof(ddesc));
    ddesc.stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC;
    memset(&hdesc, 0, sizeof(hdesc));
    hdesc.stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC;
    if (p_zeMemAllocShared(g_hx.ctx, &ddesc, &hdesc,
                           (size_t)HX_MAX_INSTR * 4u * sizeof(uint32_t), 64,
                           g_hx.dev, (void **)&g_hx.prog) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    if (p_zeMemAllocShared(g_hx.ctx, &ddesc, &hdesc, sizeof(hx_results), 64,
                           g_hx.dev, (void **)&g_hx.results) != ZE_RESULT_SUCCESS) {
        return 0;
    }
    snprintf(g_hx.info, sizeof(g_hx.info), "Level Zero HashX: %.80s",
             props.name);
    g_hx.available = 1;
    return 1;
}

int anubis_l0_hashx_available(void) {
    return hx_init();
}

const char *anubis_l0_hashx_info(void) {
    if (!hx_init()) {
        return NULL;
    }
    return g_hx.info;
}

static void hx_hex(const uint32_t w[8], char out[65]) {
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

static int hx_dispatch(const uint32_t *prog, uint32_t code_size,
                       const uint64_t keys[4], uint32_t difficulty,
                       uint32_t base, uint32_t count) {
    ze_group_count_t gc;
    uint64_t k0 = keys[0], k1 = keys[1], k2 = keys[2], k3 = keys[3];
    void *prog_ptr = g_hx.prog;
    void *res_ptr = g_hx.results;
    uint32_t groups = (count + HX_WG - 1u) / HX_WG;

    if (p_zeKernelSetArg(g_hx.kernel, 0, sizeof(void *), &prog_ptr) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 1, sizeof(uint32_t), &code_size) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 2, sizeof(uint64_t), &k0) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 3, sizeof(uint64_t), &k1) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 4, sizeof(uint64_t), &k2) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 5, sizeof(uint64_t), &k3) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 6, sizeof(uint32_t), &difficulty) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 7, sizeof(uint32_t), &base) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 8, sizeof(uint32_t), &count) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_hx.kernel, 9, sizeof(void *), &res_ptr) !=
            ZE_RESULT_SUCCESS) {
        return -1;
    }
    g_hx.results->count = 0;
    gc.groupCountX = groups;
    gc.groupCountY = 1;
    gc.groupCountZ = 1;
    if (p_zeCommandListReset(g_hx.list) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeLaunch(g_hx.list, g_hx.kernel, &gc, NULL, 0, NULL) !=
        ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeCommandListClose(g_hx.list) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeExecute(g_hx.queue, 1, &g_hx.list, NULL) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeSynchronize(g_hx.queue, UINT64_MAX) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    return 0;
}

/*
 * Returns 0 on a hit (caller re-verifies), 1 if the range was exhausted,
 * -1 on backend failure.
 */
int anubis_l0_hashx_solve(const void *state, size_t state_size, int difficulty,
                          uint64_t max_nonce, double budget_ms,
                          uint32_t *out_nonce, char out_hex[65],
                          double *out_ms) {
    uint64_t keys[4];
    static uint32_t prog[HX_MAX_INSTR * 4];
    size_t ninstr = 0;
    uint32_t chunk;
    uint64_t base = 0;
    uint64_t maxn;
    double t0;
    int rc = 1;

    if (state == NULL || out_nonce == NULL || out_hex == NULL) {
        return -1;
    }
    if (hashx_export(state, state_size, keys, prog, &ninstr) != 0) {
        return -1;
    }
    if (!hx_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_hx.mu);
    t0 = hx_now();
    memcpy(g_hx.prog, prog, ninstr * 4u * sizeof(uint32_t));
    chunk = hx_env_u32("ANUBIS_L0_HASHX_CHUNK", HX_CHUNK);
    if (chunk < 1024u) {
        chunk = 1024u;
    }
    if (chunk > (1u << 26)) {
        chunk = 1u << 26;
    }
    maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;

    while (base <= maxn) {
        uint64_t remaining = maxn - base + 1;
        uint32_t count = (uint32_t)(remaining < (uint64_t)chunk
                                        ? remaining
                                        : (uint64_t)chunk);
        if (count == 0) {
            break;
        }
        if (hx_dispatch(prog, (uint32_t)ninstr, keys, (uint32_t)difficulty,
                        (uint32_t)base, count) != 0) {
            rc = -1;
            break;
        }
        if (g_hx.results->count > 0) {
            uint32_t best = g_hx.results->nonces[0];
            uint32_t bh[8];
            memcpy(bh, g_hx.results->hashes[0], sizeof(bh));
            hx_hex(bh, out_hex);
            *out_nonce = best;
            if (out_ms != NULL) {
                *out_ms = (hx_now() - t0) * 1000.0;
            }
            rc = 0;
            break;
        }
        base += count;
        if (budget_ms > 0.0 && (hx_now() - t0) * 1000.0 > budget_ms) {
            rc = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_hx.mu);
    return rc;
}

/* Single-nonce digest for testing/debugging. */
int anubis_l0_hashx_digest(const void *state, size_t state_size,
                           uint32_t nonce, uint8_t out[32]) {
    uint64_t keys[4];
    static uint32_t prog[HX_MAX_INSTR * 4];
    size_t ninstr = 0;

    if (state == NULL || out == NULL ||
        hashx_export(state, state_size, keys, prog, &ninstr) != 0 ||
        !hx_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_hx.mu);
    memcpy(g_hx.prog, prog, ninstr * 4u * sizeof(uint32_t));
    if (hx_dispatch(prog, (uint32_t)ninstr, keys, 0u, nonce, 1u) != 0 ||
        g_hx.results->count == 0) {
        pthread_mutex_unlock(&g_hx.mu);
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        uint32_t w = g_hx.results->hashes[0][i];
        out[4 * i + 0] = (uint8_t)(w >> 24);
        out[4 * i + 1] = (uint8_t)(w >> 16);
        out[4 * i + 2] = (uint8_t)(w >> 8);
        out[4 * i + 3] = (uint8_t)w;
    }
    pthread_mutex_unlock(&g_hx.mu);
    return 0;
}
