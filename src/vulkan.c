/*
 * vulkan.c — optional Vulkan compute backend for the SHA-256 challenges.
 *
 * Loads libvulkan.so.1 at runtime (dlopen), so builds and runs on machines
 * without Vulkan and falls back to the CPU paths. One device/queue/pipeline is
 * created lazily and reused.
 *
 * The kernel (src/sha256_comp.comp -> src/sha256_comp.spv.h) hashes one
 * candidate nonce per invocation from a shared prefix midstate, matching the
 * tail layout of the CPU paths:
 *
 *   mode 0: message = prefix_ascii || decimal(nonce)
 *   mode 1: message = prefix_bytes || u32 nonce [le|be]
 *
 * Every result is re-verified by the caller with the CPU implementation, so a
 * bug in the shader cannot produce an invalid proof.
 *
 * Environment:
 *   ANUBIS_NO_VULKAN=1          disable the backend
 *   ANUBIS_VULKAN_ALLOW_CPU=1   allow a CPU-type Vulkan device (lavapipe)
 *   ANUBIS_VULKAN_DEVICE=NAME   substring match on the device name
 *   ANUBIS_VULKAN_CHUNK=N       invocations per dispatch (default 1048576)
 *   ANUBIS_VULKAN_MIN_WORK=N    minimum expected hashes before GPU is used
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <vulkan/vulkan.h>

#include "sha256_comp.spv.h"

#define VK_FUNCS(X)                                                            \
    X(vkCreateInstance)                                                        \
    X(vkDestroyInstance)                                                       \
    X(vkEnumeratePhysicalDevices)                                              \
    X(vkGetPhysicalDeviceProperties)                                           \
    X(vkGetPhysicalDeviceQueueFamilyProperties)                                \
    X(vkGetPhysicalDeviceMemoryProperties)                                     \
    X(vkCreateDevice)                                                          \
    X(vkDestroyDevice)                                                         \
    X(vkGetDeviceQueue)                                                        \
    X(vkCreateBuffer)                                                          \
    X(vkDestroyBuffer)                                                         \
    X(vkGetBufferMemoryRequirements)                                           \
    X(vkAllocateMemory)                                                        \
    X(vkFreeMemory)                                                            \
    X(vkBindBufferMemory)                                                      \
    X(vkMapMemory)                                                             \
    X(vkUnmapMemory)                                                           \
    X(vkCreateShaderModule)                                                    \
    X(vkDestroyShaderModule)                                                   \
    X(vkCreateDescriptorSetLayout)                                             \
    X(vkDestroyDescriptorSetLayout)                                            \
    X(vkCreatePipelineLayout)                                                  \
    X(vkDestroyPipelineLayout)                                                 \
    X(vkCreateComputePipelines)                                                \
    X(vkDestroyPipeline)                                                       \
    X(vkCreateDescriptorPool)                                                  \
    X(vkDestroyDescriptorPool)                                                 \
    X(vkAllocateDescriptorSets)                                                \
    X(vkUpdateDescriptorSets)                                                  \
    X(vkCreateCommandPool)                                                     \
    X(vkDestroyCommandPool)                                                    \
    X(vkAllocateCommandBuffers)                                                \
    X(vkFreeCommandBuffers)                                                    \
    X(vkBeginCommandBuffer)                                                    \
    X(vkEndCommandBuffer)                                                      \
    X(vkCmdBindPipeline)                                                       \
    X(vkCmdBindDescriptorSets)                                                 \
    X(vkCmdDispatch)                                                           \
    X(vkCmdPipelineBarrier)                                                    \
    X(vkQueueSubmit)                                                           \
    X(vkQueueWaitIdle)                                                         \
    X(vkResetCommandPool)

#define DECL(name) static PFN_##name p_##name;
VK_FUNCS(DECL)

typedef struct {
    uint32_t midstate[8];
    uint32_t prefix_len;
    uint32_t mode;        /* 0 = decimal, 1 = fixed 4-byte */
    uint32_t use_le;
    uint32_t difficulty;
    uint32_t check_bits;
    uint32_t base_nonce;
    uint32_t chunk;
} vk_params;

typedef struct {
    uint32_t count;
    uint32_t pad0;
    uint32_t pad1;
    uint32_t pad2;
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} vk_results;

static struct {
    int state; /* 0 = untouched, 1 = ready, -1 = unavailable */
    void *lib;
    VkInstance instance;
    VkPhysicalDevice phys;
    VkDevice device;
    VkQueue queue;
    uint32_t qfam;
    VkBuffer params_buf, results_buf;
    VkDeviceMemory params_mem, results_mem;
    VkDescriptorSetLayout dsl;
    VkPipelineLayout pl;
    VkPipeline pipe;
    VkDescriptorPool dpool;
    VkDescriptorSet dset;
    VkCommandPool cpool;
    VkCommandBuffer cmd;
    VkShaderModule smod;
    vk_params *params;
    vk_results *results;
    pthread_mutex_t mu;
    char name[256];
    int is_cpu;
    uint32_t vendor_id;
    uint32_t device_id;
} g_vk;

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t env_u32(const char *name, uint32_t fallback) {
    const char *s = getenv(name);
    if (s == NULL || *s == '\0') {
        return fallback;
    }
    return (uint32_t)strtoul(s, NULL, 0);
}

static int find_memory_type(uint32_t bits, VkMemoryPropertyFlags want) {
    VkPhysicalDeviceMemoryProperties mp;
    p_vkGetPhysicalDeviceMemoryProperties(g_vk.phys, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; i++) {
        if ((bits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & want) == want) {
            return (int)i;
        }
    }
    return -1;
}

static VkBuffer make_buffer(VkDeviceSize size, VkDeviceMemory *mem,
                            void **mapped) {
    VkBufferCreateInfo bci = {
        .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .size = size,
        .usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
    };
    VkBuffer buf = VK_NULL_HANDLE;
    if (p_vkCreateBuffer(g_vk.device, &bci, NULL, &buf) != VK_SUCCESS) {
        return VK_NULL_HANDLE;
    }
    VkMemoryRequirements req;
    p_vkGetBufferMemoryRequirements(g_vk.device, buf, &req);
    int idx = find_memory_type(req.memoryTypeBits,
                               VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                   VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (idx < 0) {
        p_vkDestroyBuffer(g_vk.device, buf, NULL);
        return VK_NULL_HANDLE;
    }
    VkMemoryAllocateInfo mai = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize = req.size,
        .memoryTypeIndex = (uint32_t)idx,
    };
    if (p_vkAllocateMemory(g_vk.device, &mai, NULL, mem) != VK_SUCCESS) {
        p_vkDestroyBuffer(g_vk.device, buf, NULL);
        return VK_NULL_HANDLE;
    }
    p_vkBindBufferMemory(g_vk.device, buf, *mem, 0);
    if (mapped != NULL && p_vkMapMemory(g_vk.device, *mem, 0, VK_WHOLE_SIZE, 0,
                                        mapped) != VK_SUCCESS) {
        *mapped = NULL;
    }
    return buf;
}

static int vk_init(void) {
    if (g_vk.state != 0) {
        return g_vk.state == 1;
    }
    g_vk.state = -1;
    if (getenv("ANUBIS_NO_VULKAN") != NULL) {
        return 0;
    }

    g_vk.lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (g_vk.lib == NULL) {
        return 0;
    }
#define LOAD(name)                                                             \
    p_##name = (PFN_##name)dlsym(g_vk.lib, #name);                             \
    if (p_##name == NULL) {                                                    \
        dlclose(g_vk.lib);                                                     \
        return 0;                                                              \
    }
    VK_FUNCS(LOAD)
#undef LOAD

    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "anubis-solver",
        .apiVersion = VK_API_VERSION_1_1,
    };
    VkInstanceCreateInfo ici = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app,
    };
    if (p_vkCreateInstance(&ici, NULL, &g_vk.instance) != VK_SUCCESS) {
        return 0;
    }

    uint32_t n = 0;
    if (p_vkEnumeratePhysicalDevices(g_vk.instance, &n, NULL) != VK_SUCCESS || n == 0) {
        return 0;
    }
    VkPhysicalDevice devs[16];
    if (n > 16) {
        n = 16;
    }
    if (p_vkEnumeratePhysicalDevices(g_vk.instance, &n, devs) != VK_SUCCESS) {
        return 0;
    }

    const char *want = getenv("ANUBIS_VULKAN_DEVICE");
    int allow_cpu = getenv("ANUBIS_VULKAN_ALLOW_CPU") != NULL;
    VkPhysicalDevice chosen = VK_NULL_HANDLE;
    int chosen_cpu = 0;

    for (uint32_t d = 0; d < n && chosen == VK_NULL_HANDLE; d++) {
        VkPhysicalDeviceProperties props;
        p_vkGetPhysicalDeviceProperties(devs[d], &props);
        int is_cpu = props.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU;
        if (is_cpu && !allow_cpu) {
            continue;
        }
        if (want != NULL && strstr(props.deviceName, want) == NULL) {
            continue;
        }
        uint32_t qn = 0;
        p_vkGetPhysicalDeviceQueueFamilyProperties(devs[d], &qn, NULL);
        if (qn == 0) {
            continue;
        }
        VkQueueFamilyProperties qs[16];
        if (qn > 16) {
            qn = 16;
        }
        p_vkGetPhysicalDeviceQueueFamilyProperties(devs[d], &qn, qs);
        for (uint32_t q = 0; q < qn; q++) {
            if ((qs[q].queueFlags & VK_QUEUE_COMPUTE_BIT) != 0) {
                chosen = devs[d];
                g_vk.qfam = q;
                g_vk.is_cpu = is_cpu;
                snprintf(g_vk.name, sizeof(g_vk.name), "%s", props.deviceName);
                g_vk.vendor_id = props.vendorID;
                g_vk.device_id = props.deviceID;
                break;
            }
        }
    }
    if (chosen == VK_NULL_HANDLE) {
        return 0;
    }
    g_vk.phys = chosen;
    (void)chosen_cpu;

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = g_vk.qfam,
        .queueCount = 1,
        .pQueuePriorities = &prio,
    };
    VkDeviceCreateInfo dci = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = 1,
        .pQueueCreateInfos = &qci,
    };
    if (p_vkCreateDevice(g_vk.phys, &dci, NULL, &g_vk.device) != VK_SUCCESS) {
        return 0;
    }
    p_vkGetDeviceQueue(g_vk.device, g_vk.qfam, 0, &g_vk.queue);

    g_vk.params_buf = make_buffer(sizeof(vk_params), &g_vk.params_mem,
                                  (void **)&g_vk.params);
    g_vk.results_buf = make_buffer(sizeof(vk_results), &g_vk.results_mem,
                                   (void **)&g_vk.results);
    if (g_vk.params_buf == VK_NULL_HANDLE || g_vk.results_buf == VK_NULL_HANDLE ||
        g_vk.params == NULL || g_vk.results == NULL) {
        return 0;
    }

    VkDescriptorSetLayoutBinding bindings[2] = {
        {.binding = 0,
         .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
         .descriptorCount = 1,
         .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT},
        {.binding = 1,
         .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
         .descriptorCount = 1,
         .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT},
    };
    VkDescriptorSetLayoutCreateInfo dsli = {
        .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
        .bindingCount = 2,
        .pBindings = bindings,
    };
    if (p_vkCreateDescriptorSetLayout(g_vk.device, &dsli, NULL, &g_vk.dsl) !=
        VK_SUCCESS) {
        return 0;
    }

    VkPipelineLayoutCreateInfo pli = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
        .setLayoutCount = 1,
        .pSetLayouts = &g_vk.dsl,
    };
    if (p_vkCreatePipelineLayout(g_vk.device, &pli, NULL, &g_vk.pl) != VK_SUCCESS) {
        return 0;
    }

    VkShaderModuleCreateInfo smci = {
        .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
        .codeSize = sha256_comp_spv_bytes,
        .pCode = sha256_comp_spv,
    };
    if (p_vkCreateShaderModule(g_vk.device, &smci, NULL, &g_vk.smod) != VK_SUCCESS) {
        return 0;
    }

    VkComputePipelineCreateInfo cpci = {
        .sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
        .stage = {.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
                  .stage = VK_SHADER_STAGE_COMPUTE_BIT,
                  .module = g_vk.smod,
                  .pName = "main"},
        .layout = g_vk.pl,
    };
    if (p_vkCreateComputePipelines(g_vk.device, VK_NULL_HANDLE, 1, &cpci, NULL,
                                   &g_vk.pipe) != VK_SUCCESS) {
        return 0;
    }

    VkDescriptorPoolSize psize = {
        .type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
        .descriptorCount = 2,
    };
    VkDescriptorPoolCreateInfo dpci = {
        .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
        .maxSets = 1,
        .poolSizeCount = 1,
        .pPoolSizes = &psize,
    };
    if (p_vkCreateDescriptorPool(g_vk.device, &dpci, NULL, &g_vk.dpool) !=
        VK_SUCCESS) {
        return 0;
    }
    VkDescriptorSetAllocateInfo dsai = {
        .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
        .descriptorPool = g_vk.dpool,
        .descriptorSetCount = 1,
        .pSetLayouts = &g_vk.dsl,
    };
    if (p_vkAllocateDescriptorSets(g_vk.device, &dsai, &g_vk.dset) != VK_SUCCESS) {
        return 0;
    }
    VkDescriptorBufferInfo pinfo = {g_vk.params_buf, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo rinfo = {g_vk.results_buf, 0, VK_WHOLE_SIZE};
    VkWriteDescriptorSet writes[2] = {
        {.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
         .dstSet = g_vk.dset,
         .dstBinding = 0,
         .descriptorCount = 1,
         .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
         .pBufferInfo = &pinfo},
        {.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
         .dstSet = g_vk.dset,
         .dstBinding = 1,
         .descriptorCount = 1,
         .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
         .pBufferInfo = &rinfo},
    };
    p_vkUpdateDescriptorSets(g_vk.device, 2, writes, 0, NULL);

    VkCommandPoolCreateInfo cpci2 = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .queueFamilyIndex = g_vk.qfam,
    };
    if (p_vkCreateCommandPool(g_vk.device, &cpci2, NULL, &g_vk.cpool) != VK_SUCCESS) {
        return 0;
    }
    VkCommandBufferAllocateInfo cbai = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = g_vk.cpool,
        .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        .commandBufferCount = 1,
    };
    if (p_vkAllocateCommandBuffers(g_vk.device, &cbai, &g_vk.cmd) != VK_SUCCESS) {
        return 0;
    }

    pthread_mutex_init(&g_vk.mu, NULL);
    g_vk.state = 1;
    return 1;
}

uint32_t anubis_vulkan_last_count(void) {
    if (g_vk.state != 1 || g_vk.results == NULL) {
        return 0u;
    }
    return g_vk.results->count;
}

int anubis_vulkan_available(void) {
    return vk_init();
}

const char *anubis_vulkan_info(void) {
    if (!vk_init()) {
        return NULL;
    }
    return g_vk.name;
}

static void hash_to_hex(const uint32_t h[8], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        uint32_t v = h[i];
        for (int b = 0; b < 4; b++) {
            uint8_t byte = (uint8_t)(v >> (24 - 8 * b));
            out[i * 8 + b * 2] = hex[byte >> 4];
            out[i * 8 + b * 2 + 1] = hex[byte & 15];
        }
    }
    out[64] = '\0';
}

static int dispatch_chunk(uint32_t base, uint32_t chunk) {
    g_vk.params->base_nonce = base;
    g_vk.params->chunk = chunk;
    g_vk.results->count = 0;

    VkCommandBufferBeginInfo bi = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    p_vkResetCommandPool(g_vk.device, g_vk.cpool, 0);
    if (p_vkBeginCommandBuffer(g_vk.cmd, &bi) != VK_SUCCESS) {
        return -1;
    }
    VkMemoryBarrier hb = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
        .srcAccessMask = VK_ACCESS_HOST_WRITE_BIT,
        .dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT,
    };
    p_vkCmdPipelineBarrier(g_vk.cmd, VK_PIPELINE_STAGE_HOST_BIT,
                           VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &hb, 0,
                           NULL, 0, NULL);
    p_vkCmdBindPipeline(g_vk.cmd, VK_PIPELINE_BIND_POINT_COMPUTE, g_vk.pipe);
    p_vkCmdBindDescriptorSets(g_vk.cmd, VK_PIPELINE_BIND_POINT_COMPUTE, g_vk.pl,
                              0, 1, &g_vk.dset, 0, NULL);
    uint32_t groups = (chunk + 63u) / 64u;
    p_vkCmdDispatch(g_vk.cmd, groups, 1, 1);

    VkMemoryBarrier mb = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
        .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
        .dstAccessMask = VK_ACCESS_HOST_READ_BIT,
    };
    p_vkCmdPipelineBarrier(g_vk.cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                           VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &mb, 0, NULL, 0,
                           NULL);
    if (p_vkEndCommandBuffer(g_vk.cmd) != VK_SUCCESS) {
        return -1;
    }

    VkSubmitInfo si = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount = 1,
        .pCommandBuffers = &g_vk.cmd,
    };
    if (p_vkQueueSubmit(g_vk.queue, 1, &si, VK_NULL_HANDLE) != VK_SUCCESS) {
        return -1;
    }
    if (p_vkQueueWaitIdle(g_vk.queue) != VK_SUCCESS) {
        return -1;
    }
    return 0;
}

int anubis_vulkan_bench_mode(uint64_t invocations, int mode, uint32_t prefix_len,
                             double *out_ms) {
    if (!vk_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_vk.mu);
    double t0 = now_seconds();
    memcpy(g_vk.params->midstate, (uint32_t[8]){0}, sizeof(uint32_t) * 8);
    g_vk.params->prefix_len = prefix_len;
    g_vk.params->mode = (uint32_t)mode;
    g_vk.params->use_le = 0;
    g_vk.params->difficulty = 255; /* impossible: no stores */
    g_vk.params->check_bits = 1;
    uint32_t chunk = env_u32("ANUBIS_VULKAN_CHUNK", 1u << 22);
    uint64_t done = 0;
    while (done < invocations) {
        uint32_t this_chunk = (uint32_t)((invocations - done) < chunk
                                             ? (invocations - done)
                                             : chunk);
        if (dispatch_chunk((uint32_t)done, this_chunk) != 0) {
            pthread_mutex_unlock(&g_vk.mu);
            return -1;
        }
        done += this_chunk;
    }
    if (out_ms != NULL) {
        *out_ms = (now_seconds() - t0) * 1000.0;
    }
    pthread_mutex_unlock(&g_vk.mu);
    return 0;
}

/*
 * Returns 0 on a verified-looking hit (caller must still re-verify), 1 if the
 * search space was exhausted, -1 on backend failure.
 */
int anubis_vulkan_solve(const uint32_t mid[8], uint32_t prefix_len, int mode,
                        int use_le, int difficulty, int check_bits,
                        uint64_t max_nonce, double budget_ms,
                        uint32_t *out_nonce, char out_hex[65],
                        double *out_ms) {
    if (!vk_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_vk.mu);
    double t0 = now_seconds();

    memcpy(g_vk.params->midstate, mid, sizeof(uint32_t) * 8);
    g_vk.params->prefix_len = prefix_len;
    g_vk.params->mode = (uint32_t)mode;
    g_vk.params->use_le = (uint32_t)use_le;
    g_vk.params->difficulty = (uint32_t)difficulty;
    g_vk.params->check_bits = (uint32_t)check_bits;

    uint32_t chunk = env_u32("ANUBIS_VULKAN_CHUNK", 1u << 22);
    if (chunk < 64u) {
        chunk = 64u;
    }
    if (chunk > (1u << 24)) {
        chunk = 1u << 24;
    }

    uint64_t base = 0;
    uint64_t maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;
    int rc = 1;
    while (base <= maxn) {
        uint64_t remaining = maxn - base + 1;
        uint32_t this_chunk =
            (uint32_t)(remaining < (uint64_t)chunk ? remaining : (uint64_t)chunk);
        if (this_chunk == 0) {
            break;
        }
        if (dispatch_chunk((uint32_t)base, this_chunk) != 0) {
            rc = -1;
            break;
        }
        if (g_vk.results->count > 0) {
            uint32_t nonce = g_vk.results->nonces[0];
            hash_to_hex(g_vk.results->hashes[0], out_hex);
            *out_nonce = nonce;
            if (out_ms != NULL) {
                *out_ms = (now_seconds() - t0) * 1000.0;
            }
            rc = 0;
            break;
        }
        base += this_chunk;
        if (budget_ms > 0.0 && (now_seconds() - t0) * 1000.0 > budget_ms) {
            rc = 1;
            break;
        }
    }

    pthread_mutex_unlock(&g_vk.mu);
    return rc;
}
