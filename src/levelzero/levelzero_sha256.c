/*
 * levelzero_sha256.c — oneAPI Level Zero backend for Intel GPUs.
 *
 * Level Zero is oneAPI's low-level C API. This backend mirrors the Vulkan
 * one: the SPIR-V kernel (src/sha256_pow.cl) hashes one candidate nonce per
 * work-item from a shared prefix midstate.
 *
 * The loader is dlopen()ed, so building with Level Zero headers does not add
 * a hard runtime dependency; a machine without an Intel GPU falls back to
 * Vulkan/CPU.
 *
 * Environment:
 *   ANUBIS_NO_LEVELZERO=1     disable the backend
 *   ANUBIS_L0_CHUNK=N         work-items per dispatch (default 1<<22)
 *   ZE_ENABLE_ALT_DRIVERS=... (driver discovery, standard Level Zero)
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <level_zero/ze_api.h>

#include "sha256_pow.spv.h"

typedef struct {
    uint32_t mid[8];
    uint32_t prefix_len;
    uint32_t mode;
    uint32_t use_le;
    uint32_t difficulty;
    uint32_t check_bits;
    uint32_t base_nonce;
    uint32_t chunk;
} l0_params;

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} l0_results;

typedef ze_result_t (*fn_zeInit)(ze_init_flags_t);
typedef ze_result_t (*fn_zeDriverGet)(uint32_t *, ze_driver_handle_t *);
typedef ze_result_t (*fn_zeDeviceGet)(ze_driver_handle_t, uint32_t *,
                                      ze_device_handle_t *);
typedef ze_result_t (*fn_zeDeviceGetProperties)(ze_device_handle_t,
                                                ze_device_properties_t *);
typedef ze_result_t (*fn_zeDeviceGetCommandQueueGroupProperties)(
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
typedef ze_result_t (*fn_zeCommandQueueExecuteCommandLists)(
    ze_command_queue_handle_t, uint32_t, ze_command_list_handle_t *,
    ze_fence_handle_t);
typedef ze_result_t (*fn_zeCommandQueueSynchronize)(ze_command_queue_handle_t,
                                                    uint64_t);
typedef ze_result_t (*fn_zeModuleCreate)(ze_context_handle_t,
                                         ze_device_handle_t,
                                         const ze_module_desc_t *,
                                         ze_module_handle_t *,
                                         ze_module_build_log_handle_t *);
typedef ze_result_t (*fn_zeKernelCreate)(ze_module_handle_t,
                                         const ze_kernel_desc_t *,
                                         ze_kernel_handle_t *);
typedef ze_result_t (*fn_zeKernelSetArgumentValue)(ze_kernel_handle_t,
                                                   uint32_t, size_t,
                                                   const void *);
typedef ze_result_t (*fn_zeKernelSetGroupSize)(ze_kernel_handle_t, uint32_t,
                                               uint32_t, uint32_t);
typedef ze_result_t (*fn_zeMemAllocShared)(ze_context_handle_t,
                                           const ze_device_mem_alloc_desc_t *,
                                           const ze_host_mem_alloc_desc_t *,
                                           size_t, size_t, ze_device_handle_t,
                                           void **);
typedef ze_result_t (*fn_zeModuleBuildLogGetString)(
    ze_module_build_log_handle_t, size_t *, char *);
typedef ze_result_t (*fn_zeCommandListAppendLaunchKernel)(
    ze_command_list_handle_t, ze_kernel_handle_t, const ze_group_count_t *,
    ze_event_handle_t, uint32_t, ze_event_handle_t *);

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
    l0_params *params;
    l0_results *results;
    char info[160];
} g_l0 = { 0, 0, PTHREAD_MUTEX_INITIALIZER, NULL, NULL, NULL, NULL, NULL,
           NULL, NULL, NULL, {0} };

static fn_zeInit p_zeInit;
static fn_zeDriverGet p_zeDriverGet;
static fn_zeDeviceGet p_zeDeviceGet;
static fn_zeDeviceGetProperties p_zeDeviceGetProperties;
static fn_zeDeviceGetCommandQueueGroupProperties p_zeDeviceGetQueueGroups;
static fn_zeContextCreate p_zeContextCreate;
static fn_zeCommandQueueCreate p_zeCommandQueueCreate;
static fn_zeCommandListCreate p_zeCommandListCreate;
static fn_zeCommandListClose p_zeCommandListClose;
static fn_zeCommandListReset p_zeCommandListReset;
static fn_zeCommandQueueExecuteCommandLists p_zeExecute;
static fn_zeCommandQueueSynchronize p_zeSynchronize;
static fn_zeModuleCreate p_zeModuleCreate;
static fn_zeKernelCreate p_zeKernelCreate;
static fn_zeKernelSetArgumentValue p_zeKernelSetArg;
static fn_zeKernelSetGroupSize p_zeKernelSetGroupSize;
static fn_zeMemAllocShared p_zeMemAllocShared;
static fn_zeCommandListAppendLaunchKernel p_zeLaunch;
static fn_zeModuleBuildLogGetString p_zeBuildLog;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t env_u32(const char *name, uint32_t def) {
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
    SYM(p_zeLaunch, "zeCommandListAppendLaunchKernel");
    SYM(p_zeBuildLog, "zeModuleBuildLogGetString");
#undef SYM
    return 1;
}

static int l0_fail(int step) {
    if (getenv("ANUBIS_L0_DEBUG") != NULL) {
        fprintf(stderr, "levelzero: init failed at step %d\n", step);
    }
    return 0;
}

static int l0_init(void) {
    void *h;
    uint32_t ndrv = 0, ndev = 0, ngroups = 0;
    ze_driver_handle_t drv[8];
    ze_device_handle_t dev[8];
    ze_device_properties_t props;
    ze_command_queue_group_properties_t groups[8];
    uint32_t ordinal = 0;
    int have_ordinal = 0;
    ze_context_desc_t cdesc;
    ze_command_queue_desc_t qdesc;
    ze_command_list_desc_t ldesc;
    ze_module_desc_t mdesc;
    ze_kernel_desc_t kdesc;
    ze_device_mem_alloc_desc_t ddesc;
    ze_host_mem_alloc_desc_t hdesc;
    void *parg[2];

    if (g_l0.inited) {
        return g_l0.available;
    }
    g_l0.inited = 1;
    {
        const char *off = getenv("ANUBIS_NO_LEVELZERO");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            return l0_fail(1);
        }
    }
    h = dlopen("libze_loader.so.1", RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        return l0_fail(2);
    }
    if (!load_syms(h)) {
        return l0_fail(3);
    }
    if (p_zeInit(0) != ZE_RESULT_SUCCESS) {
        return l0_fail(4);
    }
    if (p_zeDriverGet(&ndrv, NULL) != ZE_RESULT_SUCCESS || ndrv == 0) {
        return l0_fail(5);
    }
    if (ndrv > 8) {
        ndrv = 8;
    }
    if (p_zeDriverGet(&ndrv, drv) != ZE_RESULT_SUCCESS) {
        return l0_fail(6);
    }
    if (p_zeDeviceGet(drv[0], &ndev, NULL) != ZE_RESULT_SUCCESS || ndev == 0) {
        return l0_fail(7);
    }
    if (ndev > 8) {
        ndev = 8;
    }
    if (p_zeDeviceGet(drv[0], &ndev, dev) != ZE_RESULT_SUCCESS) {
        return l0_fail(8);
    }
    g_l0.dev = dev[0];
    memset(&props, 0, sizeof(props));
    props.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
    if (p_zeDeviceGetProperties(g_l0.dev, &props) != ZE_RESULT_SUCCESS) {
        return l0_fail(9);
    }

    if (p_zeDeviceGetQueueGroups(g_l0.dev, &ngroups, NULL) != ZE_RESULT_SUCCESS ||
        ngroups == 0) {
        return l0_fail(10);
    }
    if (ngroups > 8) {
        ngroups = 8;
    }
    if (p_zeDeviceGetQueueGroups(g_l0.dev, &ngroups, groups) !=
        ZE_RESULT_SUCCESS) {
        return l0_fail(11);
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
        return l0_fail(12);
    }

    memset(&cdesc, 0, sizeof(cdesc));
    cdesc.stype = ZE_STRUCTURE_TYPE_CONTEXT_DESC;
    if (p_zeContextCreate(drv[0], &cdesc, &g_l0.ctx) != ZE_RESULT_SUCCESS) {
        return l0_fail(13);
    }

    memset(&qdesc, 0, sizeof(qdesc));
    qdesc.stype = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC;
    qdesc.ordinal = ordinal;
    qdesc.index = 0;
    qdesc.mode = ZE_COMMAND_QUEUE_MODE_DEFAULT;
    qdesc.priority = ZE_COMMAND_QUEUE_PRIORITY_NORMAL;
    if (p_zeCommandQueueCreate(g_l0.ctx, g_l0.dev, &qdesc, &g_l0.queue) !=
        ZE_RESULT_SUCCESS) {
        return l0_fail(14);
    }

    memset(&ldesc, 0, sizeof(ldesc));
    ldesc.stype = ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC;
    ldesc.commandQueueGroupOrdinal = ordinal;
    if (p_zeCommandListCreate(g_l0.ctx, g_l0.dev, &ldesc, &g_l0.list) !=
        ZE_RESULT_SUCCESS) {
        return l0_fail(15);
    }

    memset(&mdesc, 0, sizeof(mdesc));
    mdesc.stype = ZE_STRUCTURE_TYPE_MODULE_DESC;
    mdesc.format = ZE_MODULE_FORMAT_IL_SPIRV;
    mdesc.inputSize = sha256_pow_spv_bytes;
    mdesc.pInputModule = (const uint8_t *)sha256_pow_spv;
    mdesc.pBuildFlags = NULL;
    {
        ze_module_build_log_handle_t log = NULL;
        ze_result_t mrc = p_zeModuleCreate(g_l0.ctx, g_l0.dev, &mdesc,
                                           &g_l0.module, &log);
        if (mrc != ZE_RESULT_SUCCESS) {
            if (getenv("ANUBIS_L0_DEBUG") != NULL) {
                fprintf(stderr, "levelzero: zeModuleCreate rc=%d log=%p\n",
                        (int)mrc, (void *)log);
            }
            if (log != NULL) {
                size_t len = 0;
                ze_result_t lrc = p_zeBuildLog(log, &len, NULL);
                fprintf(stderr, "levelzero: build log len rc=%d len=%zu\n",
                        (int)lrc, len);
                if (lrc == ZE_RESULT_SUCCESS && len > 1) {
                    char *buf = (char *)malloc(len + 1);
                    if (buf != NULL) {
                        lrc = p_zeBuildLog(log, &len, buf);
                        if (lrc == ZE_RESULT_SUCCESS) {
                            fprintf(stderr, "levelzero: module build log: %s\n",
                                    buf);
                        }
                        free(buf);
                    }
                }
            }
            return l0_fail(16);
        }
    }

    memset(&kdesc, 0, sizeof(kdesc));
    kdesc.stype = ZE_STRUCTURE_TYPE_KERNEL_DESC;
    kdesc.pKernelName = "sha256_pow";
    if (p_zeKernelCreate(g_l0.module, &kdesc, &g_l0.kernel) != ZE_RESULT_SUCCESS) {
        return l0_fail(17);
    }
    if (p_zeKernelSetGroupSize(g_l0.kernel, 64, 1, 1) != ZE_RESULT_SUCCESS) {
        return l0_fail(18);
    }

    memset(&ddesc, 0, sizeof(ddesc));
    ddesc.stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC;
    memset(&hdesc, 0, sizeof(hdesc));
    hdesc.stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC;
    if (p_zeMemAllocShared(g_l0.ctx, &ddesc, &hdesc, sizeof(l0_params), 64,
                           g_l0.dev, (void **)&g_l0.params) != ZE_RESULT_SUCCESS) {
        return l0_fail(19);
    }
    if (p_zeMemAllocShared(g_l0.ctx, &ddesc, &hdesc, sizeof(l0_results), 64,
                           g_l0.dev, (void **)&g_l0.results) != ZE_RESULT_SUCCESS) {
        return l0_fail(20);
    }
    parg[0] = g_l0.params;
    parg[1] = g_l0.results;
    if (p_zeKernelSetArg(g_l0.kernel, 0, sizeof(void *), &parg[0]) !=
            ZE_RESULT_SUCCESS ||
        p_zeKernelSetArg(g_l0.kernel, 1, sizeof(void *), &parg[1]) !=
            ZE_RESULT_SUCCESS) {
        return l0_fail(21);
    }

    snprintf(g_l0.info, sizeof(g_l0.info), "Level Zero: %.100s", props.name);
    g_l0.available = 1;
    return 1;
}

int anubis_l0_available(void) {
    return l0_init();
}

const char *anubis_l0_info(void) {
    if (!l0_init()) {
        return NULL;
    }
    return g_l0.info;
}

static void hex_from_words(const uint32_t w[8], char out[65]) {
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

static int dispatch(uint32_t base, uint32_t count) {
    ze_group_count_t gc;
    l0_params *pp = g_l0.params;

    pp->base_nonce = base;
    pp->chunk = count;
    g_l0.results->count = 0;

    gc.groupCountX = (count + 63u) / 64u;
    gc.groupCountY = 1;
    gc.groupCountZ = 1;

    if (p_zeCommandListReset(g_l0.list) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeLaunch(g_l0.list, g_l0.kernel, &gc, NULL, 0, NULL) !=
        ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeCommandListClose(g_l0.list) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeExecute(g_l0.queue, 1, &g_l0.list, NULL) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    if (p_zeSynchronize(g_l0.queue, UINT64_MAX) != ZE_RESULT_SUCCESS) {
        return -1;
    }
    return 0;
}

/*
 * Returns 0 on a hit (caller re-verifies), 1 if the range was exhausted,
 * -1 on backend failure.
 */
int anubis_l0_solve(const uint32_t mid[8], uint32_t prefix_len, int mode,
                    int use_le, int difficulty, int check_bits,
                    uint64_t max_nonce, double budget_ms, uint32_t *out_nonce,
                    char out_hex[65], double *out_ms) {
    double t0;
    uint32_t chunk;
    uint64_t base = 0;
    uint64_t maxn;
    int rc = 1;

    if (!l0_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_l0.mu);
    t0 = now_s();

    memcpy(g_l0.params->mid, mid, sizeof(uint32_t) * 8);
    g_l0.params->prefix_len = prefix_len;
    g_l0.params->mode = (uint32_t)mode;
    g_l0.params->use_le = (uint32_t)use_le;
    g_l0.params->difficulty = (uint32_t)difficulty;
    g_l0.params->check_bits = (uint32_t)check_bits;

    chunk = env_u32("ANUBIS_L0_CHUNK", 1u << 22);
    if (chunk < 4096u) {
        chunk = 4096u;
    }
    if (chunk > (1u << 24)) {
        chunk = 1u << 24;
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
        if (dispatch((uint32_t)base, count) != 0) {
            rc = -1;
            break;
        }
        if (g_l0.results->count > 0) {
            uint32_t nonce = g_l0.results->nonces[0];
            hex_from_words(g_l0.results->hashes[0], out_hex);
            *out_nonce = nonce;
            if (out_ms != NULL) {
                *out_ms = (now_s() - t0) * 1000.0;
            }
            rc = 0;
            break;
        }
        base += count;
        if (budget_ms > 0.0 && (now_s() - t0) * 1000.0 > budget_ms) {
            rc = 1;
            break;
        }
    }

    pthread_mutex_unlock(&g_l0.mu);
    return rc;
}
