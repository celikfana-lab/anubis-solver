/*
 * i915_probe.c - drive the Intel GPU through /dev/dri/renderD128 and DRM
 *                ioctls only.  No Mesa, no libOpenCL, no Level Zero, no
 *                libdrm wrappers: every interaction with the driver is one
 *                ioctl in this file.
 *
 * What it establishes, in order:
 *
 *   1. the device identity the driver exposes (I915_PARAM_*): chipset,
 *      revision, EU count, subslice count, LLC, fence count.
 *   2. the engine list (I915_QUERY / DRM_I915_QUERY_ENGINE_INFO), which on
 *      Alder Lake-P includes a compute-class (CCS) engine next to render.
 *   3. GEM allocation and mmap, and - optionally - pinning an object at a
 *      chosen virtual address (EXEC_OBJECT_PINNED).
 *   4. submission through DRM_IOCTL_I915_GEM_EXECBUFFER2 with an out fence,
 *      measured three ways:
 *        - one submission, wait, repeat  -> launch + completion latency
 *        - submit N, then wait for all   -> amortised cost, the number that
 *                                           matters if you batch work
 *        - a batch of K MI_NOOPs        -> command-stream retire rate, the
 *                                           ceiling for hand-written command
 *                                           streams
 *   5. a batch that writes a known value into the data object with
 *      MI_STORE_DWORD_IMM, read back after the fence.  That is the proof
 *      that the GPU executes a stream built here, not just that ioctls
 *      return 0.
 *
 * What it does NOT do (yet): a GPGPU dispatch.  The kernel binary needs the
 * gen12 media pipeline set up around it - state base address, an interface
 * descriptor, a media VFE state, a GPGPU walker - and i915 has no ioctl for
 * any of that; it is all commands in the batch.  Those commands and their
 * exact shape were captured from Intel's own driver by i915_dump.c, which is
 * in this directory; see README.md for the annotated capture.
 *
 * Build:  make -C src/i915raw
 * Run  :  ./build/i915-probe [--bench N] [--pipe N] [--storm K] [--pin ADDR]
 *
 * Two facts about the uapi that cost time to find, both encoded below:
 *   - batch_len must be a multiple of 8 (i915_gem_check_execbuffer), and
 *   - the batch must not be the only object in the buffer list; a
 *     single-object execbuffer returns EINVAL for anything but a tiny batch.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <drm/drm.h>
#include <drm/i915_drm.h>

#define MI_INSTR(op, flags) (((op) << 23) | (flags))
#define MI_NOOP MI_INSTR(0x00, 0)
#define MI_BATCH_BUFFER_END MI_INSTR(0x0a, 0)
/*
 * GEN4 form: four dwords (opcode, address low, address high, value).  The
 * low 8 bits of the opcode word are (length - 1).  Bit 22 selects the GGTT;
 * clear means the PPGTT virtual address, which is what i915 reports for an
 * object and what a store must use.
 */
#define MI_STORE_DWORD_IMM_GEN4 MI_INSTR(0x20, 2)

#define GEM_SIZE (1u << 20)	/* 1 MiB: a 256k-command batch fits */
#define RENDER_NODE "/dev/dri/renderD128"

static int verbose;
static uint64_t last_data_va;
static uint64_t last_batch_va;

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(1);
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

/* ------------------------------------------------------------------ */
/* device identity                                                    */

static int getparam(int fd, int param, int *out)
{
	struct drm_i915_getparam gp = { .param = param, .value = out };

	return ioctl(fd, DRM_IOCTL_I915_GETPARAM, &gp) < 0 ? -1 : 0;
}

static void show_params(int fd)
{
	static const struct {
		int id;
		const char *name;
	} params[] = {
		{ I915_PARAM_CHIPSET_ID, "chipset id" },
		{ I915_PARAM_REVISION, "revision" },
		{ I915_PARAM_HAS_LLC, "has LLC" },
		{ I915_PARAM_EU_TOTAL, "EUs" },
		{ I915_PARAM_SUBSLICE_TOTAL, "subslices" },
		{ I915_PARAM_HAS_EXECBUF2, "execbuffer2" },
		{ I915_PARAM_CS_TIMESTAMP_FREQUENCY, "cs timestamp MHz" },
		{ I915_PARAM_NUM_FENCES_AVAIL, "fences" },
	};
	unsigned i;

	printf("device\n");
	for (i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
		int v = -1;

		if (getparam(fd, params[i].id, &v) == 0)
			printf("  %-18s %d (0x%x)\n", params[i].name, v, v);
		else
			printf("  %-18s -\n", params[i].name);
	}
}

static void show_engines(int fd)
{
	static const char *classes[] = {
		"render", "video-decode", "video-enhance", "compute",
	};
	struct drm_i915_query_item item = { .query_id = DRM_I915_QUERY_ENGINE_INFO };
	struct drm_i915_query q = { .num_items = 1, .items_ptr = (uintptr_t)&item };
	struct drm_i915_query_engine_info *info;
	unsigned i;

	if (ioctl(fd, DRM_IOCTL_I915_QUERY, &q) < 0) {
		printf("engines: query failed: %s\n", strerror(errno));
		return;
	}
	if (item.length <= 0) {
		printf("engines: query returned length %d\n", item.length);
		return;
	}
	info = calloc(1, item.length);
	item.data_ptr = (uintptr_t)info;
	if (ioctl(fd, DRM_IOCTL_I915_QUERY, &q) < 0) {
		free(info);
		return;
	}
	printf("engines (%u)\n", info->num_engines);
	for (i = 0; i < info->num_engines; i++) {
		struct i915_engine_class_instance *e = &info->engines[i].engine;
		const char *cls = e->engine_class <= I915_ENGINE_CLASS_COMPUTE ?
				  classes[e->engine_class] : "?";

		printf("  %-13s class %u instance %u  caps 0x%llx%s\n",
		       cls, e->engine_class, e->engine_instance,
		       (unsigned long long)info->engines[i].capabilities,
		       e->engine_class == I915_ENGINE_CLASS_COMPUTE ? "  (CCS)" : "");
	}
	free(info);
}

/* ------------------------------------------------------------------ */
/* GEM objects                                                        */

struct bo {
	uint32_t handle;
	uint32_t size;
	uint32_t *map;
};

static void bo_create(int fd, struct bo *bo, uint32_t size)
{
	struct drm_i915_gem_create create = { .size = size };
	struct drm_i915_gem_mmap_offset mmo = { 0 };
	void *p;

	memset(bo, 0, sizeof(*bo));
	if (ioctl(fd, DRM_IOCTL_I915_GEM_CREATE, &create) < 0)
		die("GEM_CREATE");
	bo->handle = create.handle;
	bo->size = size;

	mmo.handle = bo->handle;
	mmo.flags = I915_MMAP_OFFSET_WC;
	if (ioctl(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &mmo) < 0) {
		mmo.flags = I915_MMAP_OFFSET_WB;
		if (ioctl(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &mmo) < 0)
			die("GEM_MMAP_OFFSET");
	}
	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmo.offset);
	if (p == MAP_FAILED)
		die("mmap(gem)");
	bo->map = p;
	if (verbose)
		printf("  bo handle %u size %u at %p\n", bo->handle, size, p);
}

/* ------------------------------------------------------------------ */
/* submission                                                         */

/*
 * Submit one batch.  The list is always [data, batch]: i915 rejects a
 * single-object execbuffer, and it looks for the batch in the last object.
 * `pin_data` (if nonzero) pins the data object at that virtual address, which
 * is how a caller gets an address it can write into the command stream
 * without relocations.  Returns the sync_file fd, or -1.
 */
static int submit(int fd, struct bo *batch, struct bo *data, uint32_t batch_len,
		  uint64_t pin_data)
{
	struct drm_i915_gem_exec_object2 objs[2] = { 0 };
	struct drm_i915_gem_execbuffer2 exec = { 0 };
	int fence_fd;

	objs[0].handle = data->handle;
	objs[0].flags = EXEC_OBJECT_WRITE;
	if (pin_data) {
		objs[0].offset = pin_data;
		objs[0].flags |= EXEC_OBJECT_PINNED;
	}
	objs[1].handle = batch->handle;

	exec.buffers_ptr = (uintptr_t)objs;
	exec.buffer_count = 2;
	exec.batch_len = batch_len;
	exec.flags = I915_EXEC_FENCE_OUT | I915_EXEC_NO_RELOC;

	if (ioctl(fd, DRM_IOCTL_I915_GEM_EXECBUFFER2, &exec) < 0)
		return -1;

	/* the kernel hands back the virtual address it gave each object */
	last_data_va = objs[0].offset;
	last_batch_va = objs[1].offset;
	fence_fd = (int)(exec.rsvd2 >> 32);
	return fence_fd;
}

static int wait_fence(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	return poll(&pfd, 1, timeout_ms) > 0 ? 0 : -1;
}

static void fill_end(uint32_t *p, unsigned ndw)
{
	unsigned i;

	for (i = 0; i + 1 < ndw; i++)
		p[i] = MI_NOOP;
	p[ndw - 1] = MI_BATCH_BUFFER_END;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	unsigned bench = 200, pipe = 256, storm = 0, warmup = 400;
	uint64_t pin = 0;
	int fd, i;
	struct bo batch, data;
	int fence;
	double t0, t1;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--bench") && i + 1 < argc)
			bench = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--pipe") && i + 1 < argc)
			pipe = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--storm") && i + 1 < argc)
			storm = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--warmup") && i + 1 < argc)
			warmup = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--pin") && i + 1 < argc)
			pin = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "-v"))
			verbose = 1;
		else {
			fprintf(stderr, "usage: %s [--bench N] [--pipe N] "
				"[--storm K] [--pin ADDR] [-v]\n", argv[0]);
			return 2;
		}
	}

	fd = open(RENDER_NODE, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		die("open " RENDER_NODE);

	show_params(fd);
	show_engines(fd);

	bo_create(fd, &batch, GEM_SIZE);
	bo_create(fd, &data, GEM_SIZE);
	data.map[0] = 0x11111111;

	/*
	 * The iGPU idles its clocks: a benchmark run on a cold GPU measures the
	 * ramp, not the hardware.  Prime it for a while first, then measure.
	 */
	if (warmup) {
		double end = now_ms() + warmup;

		fill_end(batch.map, 2);
		while (now_ms() < end) {
			fence = submit(fd, &batch, &data, 8, pin);
			if (fence < 0)
				die("warmup submit");
			wait_fence(fence, 2000);
			close(fence);
		}
		if (verbose)
			printf("warmed up for %u ms\n", warmup);
	}

	/* --- sequential: submit, wait, repeat --------------------------- */
	fill_end(batch.map, 2);
	t0 = now_ms();
	for (i = 0; i < (int)bench; i++) {
		fence = submit(fd, &batch, &data, 8, pin);
		if (fence < 0) {
			fprintf(stderr, "submit failed at %d: %s\n", i, strerror(errno));
			return 1;
		}
		if (wait_fence(fence, 2000) < 0) {
			fprintf(stderr, "fence %d timed out\n", i);
			return 1;
		}
		close(fence);
	}
	t1 = now_ms();
	printf("\nsequential submissions\n");
	printf("  %u submit+wait cycles in %.1f ms\n", bench, t1 - t0);
	printf("  %.2f us per submission (launch + execute + fence wakeup)\n",
	       (t1 - t0) * 1000.0 / bench);

	/* --- pipelined: submit N first, then wait for all --------------- */
	if (pipe) {
		int *fds = calloc(pipe, sizeof(*fds));
		unsigned k, ok = 0;

		t0 = now_ms();
		for (k = 0; k < pipe; k++) {
			fds[k] = submit(fd, &batch, &data, 8, pin);
			if (fds[k] < 0) {
				fprintf(stderr, "pipeline submit %u failed: %s\n",
					k, strerror(errno));
				return 1;
			}
		}
		for (k = 0; k < pipe; k++)
			if (wait_fence(fds[k], 10000) == 0)
				ok++;
		t1 = now_ms();
		printf("\npipelined submissions\n");
		printf("  %u submitted, %u completed in %.1f ms\n", pipe, ok, t1 - t0);
		printf("  %.2f us per submission (no per-submit stall)\n",
		       (t1 - t0) * 1000.0 / pipe);
		printf("  %.0f submissions/s\n", pipe * 1e3 / (t1 - t0));
		for (k = 0; k < pipe; k++)
			close(fds[k]);
		free(fds);
	}

	/* --- command stream: retire rate of a hand-written batch -------- */
	if (storm) {
		unsigned ndw = storm + 2;

		if (ndw & 1)
			ndw++;			/* batch_len must be a multiple of 8 */
		if (ndw * 4 > GEM_SIZE)
			ndw = GEM_SIZE / 4;
		fill_end(batch.map, ndw);

		/*
		 * The command streamer's rate depends on the GPU's current clock,
		 * which the driver powers up and down per submission, so take the
		 * best of three and say so.
		 */
		{
			double best = 1e9;
			unsigned rep;

			for (rep = 0; rep < 3; rep++) {
				t0 = now_ms();
				fence = submit(fd, &batch, &data, ndw * 4, pin);
				if (fence < 0)
					die("storm submit");
				if (wait_fence(fence, 60000) < 0)
					die("storm fence");
				close(fence);
				t1 = now_ms();
				if (t1 - t0 < best)
					best = t1 - t0;
			}
			printf("\ncommand stream (best of 3)\n");
			printf("  %u MI_NOOPs (%.0f KiB) in %.3f ms\n", ndw - 2,
			       ndw * 4 / 1024.0, best);
			printf("  %.1f M commands/s\n", (ndw - 2) / (best * 1e3));
			printf("  %.0f MB/s of command bytes\n", ndw * 4.0 / best / 1000.0);
		}
	}

	/* --- store dword: prove that our stream executed ---------------- */
	{
		uint32_t *p = batch.map;
		int fence2;

		/* learn the address the driver gave the data object */
		fill_end(batch.map, 2);
		fence = submit(fd, &batch, &data, 8, pin);
		if (fence < 0)
			die("learn submit");
		if (wait_fence(fence, 2000) < 0)
			die("learn fence");
		close(fence);

		memset(batch.map, 0, 64);
		memset(data.map, 0, 64);
		p = batch.map;
		*p++ = MI_STORE_DWORD_IMM_GEN4;
		*p++ = (uint32_t)last_data_va;
		*p++ = (uint32_t)(last_data_va >> 32);
		*p++ = 0xcafebabe;
		*p++ = MI_NOOP;
		*p++ = MI_BATCH_BUFFER_END;

		fence2 = submit(fd, &batch, &data, 24, pin);
		if (fence2 < 0) {
			printf("\nstore dword: execbuffer failed: %s\n", strerror(errno));
			return 1;
		}
		if (wait_fence(fence2, 2000) < 0)
			die("store fence");
		close(fence2);

		printf("\nstore dword\n");
		printf("  data object at VA 0x%llx (batch at 0x%llx)\n",
		       (unsigned long long)last_data_va,
		       (unsigned long long)last_batch_va);
		printf("  data[0] = 0x%08x  %s\n", data.map[0],
		       data.map[0] == 0xcafebabe ?
		       "OK - the GPU executed the stream this program built" :
		       "FAILED - no store landed");
		if (data.map[0] != 0xcafebabe)
			return 1;
	}

	printf("\nraw i915 submission path works.\n");
	return 0;
}
