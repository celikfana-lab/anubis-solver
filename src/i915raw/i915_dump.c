/*
 * i915_dump.c - LD_PRELOAD interceptor that records exactly what a real
 *               Intel driver (NEO/IGC) submits to /dev/dri/renderD128.
 *
 * Why: the raw-i915 GPGPU path has to build the same command stream the
 * driver builds (state base address, interface descriptor, media state,
 * walker). Rather than guess that stream from the PRMs, we let the vendor
 * stack produce it once and read it back. The driver keeps running normally;
 * this only observes.
 *
 *   gcc -O2 -shared -fPIC -o /tmp/i915_dump.so i915_dump.c -ldl
 *   sudo? no:  LD_PRELOAD=/tmp/i915_dump.so ./clrun
 *   -> /tmp/i915dump/log.txt and one .bin per buffer per submission
 *
 * Buffers are recovered by handle: GEM_CREATE / GEM_USERPTR give us the
 * handle, and we mmap GEM objects ourselves (MMAP_OFFSET) or read a userptr
 * straight from the address the application registered.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/mman.h>

#include <drm/drm.h>
#include <drm/i915_drm.h>

#define MAX_BO 4096
#define OUTDIR "/tmp/i915dump"

struct boent {
	uint32_t handle;
	uint32_t size;
	void *userptr;
	void *map;
};

static struct boent bos[MAX_BO];
static int nbos;
static int init;
static int (*real_ioctl)(int, unsigned long, void *);
static int sub_count;
static FILE *logf;

static int raw_ioctl(int fd, unsigned long req, void *arg)
{
	return (int)syscall(SYS_ioctl, fd, req, arg);
}

static struct boent *find_bo(uint32_t handle)
{
	int i;

	for (i = 0; i < nbos; i++)
		if (bos[i].handle == handle)
			return &bos[i];
	return NULL;
}

static struct boent *add_bo(uint32_t handle, uint32_t size)
{
	struct boent *b;

	if (nbos >= MAX_BO)
		return NULL;
	b = &bos[nbos++];
	b->handle = handle;
	b->size = size;
	b->userptr = NULL;
	b->map = NULL;
	return b;
}

static void *map_bo(int fd, struct boent *b)
{
	struct drm_i915_gem_mmap_offset mmo = { .handle = b->handle };
	void *p;

	if (b->map)
		return b->map;
	if (b->userptr) {
		b->map = b->userptr;
		return b->map;
	}
	mmo.flags = I915_MMAP_OFFSET_WC;
	if (raw_ioctl(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &mmo) < 0)
		return NULL;
	p = mmap(NULL, b->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmo.offset);
	if (p == MAP_FAILED)
		return NULL;
	b->map = p;
	return p;
}

__attribute__((constructor))
static void init_dump(void)
{
	real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	mkdir(OUTDIR, 0755);
	logf = fopen(OUTDIR "/log.txt", "w");
	init = 1;
}

__attribute__((destructor))
static void fini_dump(void)
{
	if (logf)
		fclose(logf);
}

static void dump_buffer(int fd, struct boent *b, int sub, int idx, const char *tag)
{
	char path[256];
	void *p;
	FILE *f;

	p = map_bo(fd, b);
	if (!p)
		return;
	snprintf(path, sizeof(path), OUTDIR "/sub%03d-%s-idx%d-h%u.bin",
		 sub, tag, idx, b->handle);
	f = fopen(path, "wb");
	if (!f)
		return;
	fwrite(p, 1, b->size, f);
	fclose(f);
}

static void on_execbuffer(int fd, struct drm_i915_gem_execbuffer2 *exec)
{
	struct drm_i915_gem_exec_object2 *objs;
	unsigned i;
	int sub = ++sub_count;
	struct boent *batch;

	if (!logf)
		return;
	objs = (void *)(uintptr_t)exec->buffers_ptr;
	if (!objs)
		return;
	batch = exec->buffer_count ? find_bo(objs[exec->buffer_count - 1].handle) : NULL;

	fprintf(logf, "\n=== submission %d: fd %d, %u objects, batch_len %u, "
		"batch_start %u, flags 0x%llx, rsvd1 0x%llx\n",
		sub, fd, exec->buffer_count, exec->batch_len,
		exec->batch_start_offset, (unsigned long long)exec->flags,
		(unsigned long long)exec->rsvd1);
	fprintf(logf, "SUB %d objs %u batch_handle %u batch_len %u batch_start %u "
		"flags 0x%llx ctx 0x%llx\n", sub, exec->buffer_count,
		batch ? batch->handle : 0, exec->batch_len, exec->batch_start_offset,
		(unsigned long long)exec->flags, (unsigned long long)exec->rsvd1);
	for (i = 0; i < exec->buffer_count; i++) {
		struct boent *b = find_bo(objs[i].handle);

		fprintf(logf, "  [%u] handle %u (%u bytes) va 0x%llx flags 0x%llx "
			"relocs %u align %llu\n",
			i, objs[i].handle, b ? b->size : 0,
			(unsigned long long)objs[i].offset,
			(unsigned long long)objs[i].flags,
			objs[i].relocation_count,
			(unsigned long long)objs[i].alignment);
		fprintf(logf, "OBJ %d %d %u %u 0x%llx 0x%llx %s\n", sub, (int)i,
			objs[i].handle, b ? b->size : 0,
			(unsigned long long)objs[i].offset,
			(unsigned long long)objs[i].flags,
			b && b->size <= (64u << 20) ? "dumped" : "skipped");
		if (objs[i].relocation_count && objs[i].relocs_ptr) {
			struct drm_i915_gem_relocation_entry *r =
				(void *)(uintptr_t)objs[i].relocs_ptr;
			unsigned j;

			for (j = 0; j < objs[i].relocation_count && j < 32; j++)
				fprintf(logf, "      reloc[%u] off 0x%llx target %u "
					"presumed 0x%llx rd 0x%x wd 0x%x\n",
					j, (unsigned long long)r[j].offset,
					r[j].target_handle,
					(unsigned long long)r[j].presumed_offset,
					r[j].read_domains, r[j].write_domain);
		}
		if (b && b->size <= (64u << 20))
			dump_buffer(fd, b, sub, (int)i, "obj");
	}

	/* the batch is the last object in an execbuffer2 */
	if (batch) {
		fprintf(logf, "  batch = handle %u at va 0x%llx, %u bytes\n",
			batch->handle,
			(unsigned long long)objs[exec->buffer_count - 1].offset,
			exec->batch_len);
		dump_buffer(fd, batch, sub, (int)exec->buffer_count - 1, "batch");
	}
	fflush(logf);
}

int ioctl(int fd, unsigned long req, void *arg)
{
	if (!init)
		init_dump();

	switch (req) {
	case DRM_IOCTL_I915_GEM_CREATE: {
		struct drm_i915_gem_create *c = arg;
		int r = real_ioctl(fd, req, arg);

		if (r == 0)
			add_bo(c->handle, c->size);
		return r;
	}
	case DRM_IOCTL_I915_GEM_CREATE_EXT: {
		struct drm_i915_gem_create_ext *c = arg;
		int r = real_ioctl(fd, req, arg);

		if (r == 0)
			add_bo(c->handle, c->size);
		return r;
	}
	case DRM_IOCTL_I915_GEM_USERPTR: {
		struct drm_i915_gem_userptr *u = arg;
		int r = real_ioctl(fd, req, arg);

		if (r == 0) {
			struct boent *b = add_bo(u->handle, u->user_size);

			if (b)
				b->userptr = (void *)(uintptr_t)u->user_ptr;
		}
		return r;
	}
	case DRM_IOCTL_I915_GEM_EXECBUFFER2:
	case DRM_IOCTL_I915_GEM_EXECBUFFER2_WR:
		on_execbuffer(fd, arg);
		break;
	default:
		break;
	}
	return real_ioctl(fd, req, arg);
}
