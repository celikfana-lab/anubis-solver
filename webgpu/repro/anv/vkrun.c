// vkrun.c — dispatch one SPIR-V compute shader on Vulkan directly, no Chrome,
// no Dawn, no Tint. Answers the only question the WebGPU test cannot: is the
// wrong result a property of the SPIR-V or of the runtime that produced it?
//
//   gcc -O1 -o vkrun vkrun.c -lvulkan
//   ./vkrun hashx.spv [base] [count] [difficulty]
//
// Layouts must match webgpu/hashx.wgsl:
//   Params  { u32 code_size, difficulty, base, count }          16 bytes
//   Results { u32 total, hits, pad0, pad1,
//             u32 nonces[8], u32 hashes[64] }                  304 bytes
#include <vulkan/vulkan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { VkResult r = (x); if (r != VK_SUCCESS) { \
    fprintf(stderr, "FAILED %s -> %d (line %d)\n", #x, r, __LINE__); exit(1); } } while (0)

static uint32_t *read_file(const char *path, size_t *bytes) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint32_t *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("read"); exit(1); }
    fclose(f);
    *bytes = (size_t)n;
    return buf;
}

static uint32_t mem_type(VkPhysicalDevice pd, uint32_t bits, VkMemoryPropertyFlags want) {
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(pd, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; i++)
        if ((bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & want) == want) return i;
    fprintf(stderr, "no host-visible memory type\n");
    exit(1);
}

static void make_buffer(VkDevice dev, VkPhysicalDevice pd, VkDeviceSize size,
                        VkBufferUsageFlags usage, VkBuffer *buf, VkDeviceMemory *mem,
                        void **mapped) {
    VkBufferCreateInfo bi = { .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
                              .size = size, .usage = usage, .sharingMode = VK_SHARING_MODE_EXCLUSIVE };
    CHECK(vkCreateBuffer(dev, &bi, NULL, buf));
    VkMemoryRequirements req;
    vkGetBufferMemoryRequirements(dev, *buf, &req);
    VkMemoryAllocateInfo ai = { .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                                .allocationSize = req.size,
                                .memoryTypeIndex = mem_type(pd, req.memoryTypeBits,
                                    VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) };
    CHECK(vkAllocateMemory(dev, &ai, NULL, mem));
    CHECK(vkBindBufferMemory(dev, *buf, *mem, 0));
    CHECK(vkMapMemory(dev, *mem, 0, size, 0, mapped));
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s shader.spv [base] [count] [difficulty]\n", argv[0]); return 2; }
    uint32_t base = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 0) : 0;
    uint32_t count = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 0) : 1;
    uint32_t difficulty = argc > 4 ? (uint32_t)strtoul(argv[4], NULL, 0) : 0;

    size_t code_bytes;
    uint32_t *code = read_file(argv[1], &code_bytes);

    VkApplicationInfo app = { .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
                              .pApplicationName = "anubis-hashx-anv-repro",
                              .apiVersion = VK_API_VERSION_1_0 };
    VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
                                 .pApplicationInfo = &app };
    VkInstance inst;
    CHECK(vkCreateInstance(&ici, NULL, &inst));

    uint32_t ndev = 0;
    CHECK(vkEnumeratePhysicalDevices(inst, &ndev, NULL));
    if (!ndev) { fprintf(stderr, "no Vulkan devices\n"); return 1; }
    VkPhysicalDevice *pds = calloc(ndev, sizeof(*pds));
    CHECK(vkEnumeratePhysicalDevices(inst, &ndev, pds));

    VkPhysicalDevice pd = VK_NULL_HANDLE;
    uint32_t qfam = 0;
    for (uint32_t d = 0; d < ndev && pd == VK_NULL_HANDLE; d++) {
        VkPhysicalDeviceProperties p;
        vkGetPhysicalDeviceProperties(pds[d], &p);
        uint32_t nq = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(pds[d], &nq, NULL);
        VkQueueFamilyProperties *qs = calloc(nq, sizeof(*qs));
        vkGetPhysicalDeviceQueueFamilyProperties(pds[d], &nq, qs);
        for (uint32_t q = 0; q < nq; q++) {
            if (qs[q].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                fprintf(stderr, "device: %s | api %u.%u.%u\n", p.deviceName,
                        VK_VERSION_MAJOR(p.apiVersion),
                        VK_VERSION_MINOR(p.apiVersion), VK_VERSION_PATCH(p.apiVersion));
                pd = pds[d]; qfam = q; break;
            }
        }
        free(qs);
    }
    if (pd == VK_NULL_HANDLE) { fprintf(stderr, "no compute queue\n"); return 1; }

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = { .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
                                    .queueFamilyIndex = qfam, .queueCount = 1, .pQueuePriorities = &prio };
    VkDeviceCreateInfo dci = { .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
                               .queueCreateInfoCount = 1, .pQueueCreateInfos = &qci };
    VkDevice dev;
    CHECK(vkCreateDevice(pd, &dci, NULL, &dev));
    VkQueue queue;
    vkGetDeviceQueue(dev, qfam, 0, &queue);

    VkShaderModuleCreateInfo smi = { .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
                                     .codeSize = code_bytes, .pCode = code };
    VkShaderModule sm;
    CHECK(vkCreateShaderModule(dev, &smi, NULL, &sm));

    // one uniform (params) and one storage (results), both host-visible so the
    // test needs no staging copies and no barriers
    VkDescriptorSetLayoutBinding binds[2] = {
        { .binding = 0, .descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
          .descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT },
        { .binding = 1, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
          .descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT },
    };
    VkDescriptorSetLayoutCreateInfo dslci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
                                              .bindingCount = 2, .pBindings = binds };
    VkDescriptorSetLayout dsl;
    CHECK(vkCreateDescriptorSetLayout(dev, &dslci, NULL, &dsl));

    VkPipelineLayoutCreateInfo plci = { .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
                                        .setLayoutCount = 1, .pSetLayouts = &dsl };
    VkPipelineLayout pl;
    CHECK(vkCreatePipelineLayout(dev, &plci, NULL, &pl));

    VkComputePipelineCreateInfo cpci = {
        .sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
        .stage = { .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
                   .stage = VK_SHADER_STAGE_COMPUTE_BIT, .module = sm, .pName = "main" },
        .layout = pl,
    };
    VkPipeline pipe;
    CHECK(vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cpci, NULL, &pipe));

    VkBuffer pbuf, rbuf;
    VkDeviceMemory pmem, rmem;
    uint32_t *pmap, *rmap;
    make_buffer(dev, pd, 16, VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT, &pbuf, &pmem, (void **)&pmap);
    make_buffer(dev, pd, 304, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, &rbuf, &rmem, (void **)&rmap);

    pmap[0] = 0; pmap[1] = difficulty; pmap[2] = base; pmap[3] = count;
    memset(rmap, 0, 304);

    VkDescriptorPoolSize ps[2] = {
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1 }, { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1 } };
    VkDescriptorPoolCreateInfo dpci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
                                        .maxSets = 1, .poolSizeCount = 2, .pPoolSizes = ps };
    VkDescriptorPool pool;
    CHECK(vkCreateDescriptorPool(dev, &dpci, NULL, &pool));
    VkDescriptorSetAllocateInfo dsai = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
                                         .descriptorPool = pool, .descriptorSetCount = 1, .pSetLayouts = &dsl };
    VkDescriptorSet ds;
    CHECK(vkAllocateDescriptorSets(dev, &dsai, &ds));

    VkDescriptorBufferInfo pbi = { pbuf, 0, 16 }, rbi = { rbuf, 0, 304 };
    VkWriteDescriptorSet w[2] = {
        { .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = ds, .dstBinding = 0,
          .descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, .pBufferInfo = &pbi },
        { .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = ds, .dstBinding = 1,
          .descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .pBufferInfo = &rbi },
    };
    vkUpdateDescriptorSets(dev, 2, w, 0, NULL);

    VkCommandPoolCreateInfo cpi = { .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
                                    .queueFamilyIndex = qfam };
    VkCommandPool cpool;
    CHECK(vkCreateCommandPool(dev, &cpi, NULL, &cpool));
    VkCommandBufferAllocateInfo cbai = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
                                         .commandPool = cpool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
                                         .commandBufferCount = 1 };
    VkCommandBuffer cb;
    CHECK(vkAllocateCommandBuffers(dev, &cbai, &cb));
    VkCommandBufferBeginInfo cbbi = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    CHECK(vkBeginCommandBuffer(cb, &cbbi));
    vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, NULL);
    vkCmdDispatch(cb, (count + 63) / 64, 1, 1);
    CHECK(vkEndCommandBuffer(cb));

    VkSubmitInfo si = { .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
                        .commandBufferCount = 1, .pCommandBuffers = &cb };
    CHECK(vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE));
    CHECK(vkQueueWaitIdle(queue));

    if (getenv("RAW")) {
        printf("raw:");
        for (int i = 0; i < 18; i++) printf(" %08x", rmap[12 + i]);
        printf("\n");
    }
    printf("total=%u\n", rmap[0]);
    for (uint32_t s = 0; s < rmap[0] && s < 8; s++) {
        const uint32_t *h = rmap + 12 + s * 8;
        printf("nonce=%u digest=", rmap[4 + s]);
        for (int i = 0; i < 4; i++) {
            uint64_t v = (uint64_t)h[2 * i] | ((uint64_t)h[2 * i + 1] << 32);
            for (int b = 0; b < 8; b++) printf("%02x", (unsigned)((v >> (8 * b)) & 0xff));
        }
        printf("\n");
    }
    return 0;
}
