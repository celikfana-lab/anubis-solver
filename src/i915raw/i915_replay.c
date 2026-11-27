/*
 * i915_replay.c - run a dispatch that Intel's driver built, from our own
 *                 process, through nothing but i915 ioctls.
 *
 * The idea: a GPGPU dispatch is not an ioctl, it is a batch buffer full of
 * commands (state base address, an interface descriptor, a media VFE state,
 * a GPGPU walker, a pipe control).  i915_dump.c recorded one such dispatch
 * from the vendor stack, together with the contents of every GEM object it
 * referenced.  This program recreates those objects at the *same* virtual
 * addresses (EXEC_OBJECT_PINNED + EXEC_OBJECT_SUPPORTS_48B_ADDRESS) and
 * submits the same submissions in the same order.  No address in the batch
 * has to be patched, because nothing moved.
 *
 * It is a replay, not a dispatcher: the nonce range, the work group count and
 * the kernel are whatever the capture says.  What it proves is that the whole
 * compute path - not just an empty batch - runs on raw i915 from userspace.
 *
 *   LD_PRELOAD=./i915_dump.so ./clrun          # produce /tmp/i915dump
 *   ./i915-replay --dump /tmp/i915dump [--upto N] [--bench N]
 *
 * The capture must be produced on the same kernel: the addresses and the
 * command encodings are specific to this driver generation.
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
#include <sys/stat.h>

#include <drm/drm.h>
#include <drm/i915_drm.h>

#define MAX_SUBS 64
#define MAX_OBJ 32

struct obj {
	uint32_t handle;
	uint32_t size;
	uint64_t va;
	uint64_t flags;
	uint32_t *map;
};

struct sub {
	unsigned n;
	struct obj objs[MAX_OBJ];
	uint32_t batch_idx;
	uint32_t batch_len;
	uint32_t batch_start;
	uint64_t flags;
};

static const char *dumpdir = "/tmp/i915dump";

struct created {
	uint64_t va;
	uint32_t *map;
	uint32_t size;
};
static struct created created[1024];
static unsigned ncreated;

/*
 * The walker stores the payload as a 32-bit low address; the high half comes
 * from the general state base.  We only need to find which of our objects
 * contains it, so match on the low 32 bits.
 */
static struct created *find_low(uint32_t low, unsigned *off)
{
	unsigned i;

	for (i = 0; i < ncreated; i++) {
		uint32_t base = (uint32_t)created[i].va;

		if (low >= base && low - base < created[i].size) {
			if (off)
				*off = low - base;
			return &created[i];
		}
	}
	return NULL;
}

static struct created *find_created(uint64_t va)
{
	unsigned i;

	for (i = 0; i < ncreated; i++)
		if (created[i].va == va)
			return &created[i];
	return NULL;
}
static int verbose;
static int fd;

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
/* parse the manifest written by i915_dump.c                          */

static void parse_manifest(struct sub *subs, unsigned *nsubs)
{
	char path[512], line[512];
	FILE *f;
	unsigned cur = 0, have = 0;

	snprintf(path, sizeof(path), "%s/log.txt", dumpdir);
	f = fopen(path, "r");
	if (!f)
		die("open log.txt (run the OpenCL harness under i915_dump.so first)");

	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "OBJ ", 4)) {
			unsigned sub, idx, handle, size;
			unsigned long long va, fl;
			struct obj *o;

			if (have == 0)
				continue;
			if (sscanf(line, "OBJ %u %u %u %u %llx %llx",
				   &sub, &idx, &handle, &size, &va, &fl) != 6)
				continue;
			if (idx >= MAX_OBJ)
				continue;
			o = &subs[have - 1].objs[idx];
			o->handle = handle;
			o->size = size;
			o->va = va;
			o->flags = fl;
			subs[have - 1].n = idx + 1 > subs[have - 1].n ?
					   idx + 1 : subs[have - 1].n;
			if (verbose)
				printf("  obj idx %u handle %u size %u va 0x%llx\n",
				       idx, handle, size, va);
		} else if (!strncmp(line, "SUB ", 4)) {
			unsigned count, bh, len, start;
			unsigned long long fl, ctx;
			struct sub *s;

			if (have >= MAX_SUBS)
				break;
			if (sscanf(line, "SUB %u objs %u batch_handle %u batch_len %u "
				   "batch_start %u flags 0x%llx ctx 0x%llx",
				   &cur, &count, &bh, &len, &start, &fl, &ctx) != 7)
				continue;
			s = &subs[have++];
			memset(s, 0, sizeof(*s));
			s->batch_len = len;
			s->batch_start = start;
			s->flags = fl;
		}
	}
	fclose(f);
	*nsubs = have;
	if (!have)
		fprintf(stderr, "no submissions in the manifest\n");
}

/* ------------------------------------------------------------------ */

static void create_object(struct obj *o, unsigned subnum, unsigned idx,
			  uint32_t file_handle)
{
	struct drm_i915_gem_create create = { .size = o->size };
	struct drm_i915_gem_mmap_offset mmo = { 0 };
	char path[512], file[512];
	struct stat st;
	FILE *f;
	void *p;

	if (verbose)
		printf("    idx %u handle %u %u bytes at 0x%llx\n",
		       idx, o->handle, o->size, (unsigned long long)o->va);

	snprintf(file, sizeof(file), "%s/sub%03u-obj-idx%u-h%u.bin",
		 dumpdir, subnum, idx, file_handle);
	if (stat(file, &st) < 0 || (uint32_t)st.st_size != o->size) {
		fprintf(stderr, "  missing or short dump %s (%lld bytes, want %u)\n",
			file, (long long)st.st_size, o->size);
		exit(1);
	}

	if (ioctl(fd, DRM_IOCTL_I915_GEM_CREATE, &create) < 0)
		die("GEM_CREATE");
	o->handle = create.handle;
	mmo.handle = o->handle;
	mmo.flags = I915_MMAP_OFFSET_WC;
	if (ioctl(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &mmo) < 0)
		die("GEM_MMAP_OFFSET");
	p = mmap(NULL, o->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmo.offset);
	if (p == MAP_FAILED)
		die("mmap");
	o->map = p;

	f = fopen(file, "rb");
	if (!f)
		die("fopen dump");
	if (fread(o->map, 1, o->size, f) != o->size)
		die("fread dump");
	fclose(f);
	if (verbose)
		sprintf(path, "-");
}

static int submit(struct sub *s, uint32_t ctx)
{
	struct drm_i915_gem_exec_object2 objs[MAX_OBJ] = { 0 };
	struct drm_i915_gem_execbuffer2 exec = { 0 };
	struct pollfd pfd;
	unsigned i;
	int fence_fd;

	for (i = 0; i < s->n; i++) {
		objs[i].handle = s->objs[i].handle;
		objs[i].offset = s->objs[i].va;
		objs[i].flags = EXEC_OBJECT_PINNED |
				EXEC_OBJECT_SUPPORTS_48B_ADDRESS |
				(s->objs[i].flags & EXEC_OBJECT_WRITE);
	}
	exec.buffers_ptr = (uintptr_t)objs;
	exec.buffer_count = s->n;
	exec.batch_start_offset = s->batch_start;
	exec.batch_len = s->batch_len;
	exec.flags = I915_EXEC_FENCE_OUT | (s->flags & I915_EXEC_NO_RELOC);
	exec.rsvd1 = ctx;

	if (ioctl(fd, DRM_IOCTL_I915_GEM_EXECBUFFER2, &exec) < 0) {
		fprintf(stderr, "execbuffer: %s\n", strerror(errno));
		return -1;
	}
	fence_fd = (int)(exec.rsvd2 >> 32);
	pfd.fd = fence_fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 30000) <= 0) {
		fprintf(stderr, "fence timed out\n");
		close(fence_fd);
		return -1;
	}
	close(fence_fd);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned nsubs = 0, upto = 0, bench = 1, nonces = 4194304;
	struct { uint64_t va; uint32_t off, val; } pokes[16];
	unsigned npokes = 0;
	uint64_t clear_va = 0;
	unsigned solve_diff = 0, have_solve = 0;
	uint64_t solve_base = 0, solve_count = 0;
	uint32_t ctx;
	struct sub *subs;
	struct drm_i915_gem_vm_control vm = { 0 };
	struct drm_i915_gem_context_create_ext_setparam sp = { 0 };
	struct drm_i915_gem_context_create_ext cc = { 0 };
	unsigned i, j;
	int argi;
	double t0, t1;

	for (argi = 1; argi < argc; argi++) {
		if (!strcmp(argv[argi], "--dump") && argi + 1 < argc)
			dumpdir = argv[++argi];
		else if (!strcmp(argv[argi], "--upto") && argi + 1 < argc)
			upto = strtoul(argv[++argi], NULL, 0);
		else if (!strcmp(argv[argi], "--bench") && argi + 1 < argc)
			bench = strtoul(argv[++argi], NULL, 0);
		else if (!strcmp(argv[argi], "--nonces") && argi + 1 < argc)
			nonces = strtoul(argv[++argi], NULL, 0);
		else if (!strcmp(argv[argi], "--poke") && argi + 1 < argc) {
			unsigned long long va, off, val;

			if (sscanf(argv[++argi], "%llx:%llx:%llx", &va, &off, &val) != 3) {
				fprintf(stderr, "poke wants VA:OFFSET:VALUE in hex\n");
				return 2;
			}
			pokes[npokes].va = va;
			pokes[npokes].off = off;
			pokes[npokes].val = val;
			npokes++;
		} else if (!strcmp(argv[argi], "--solve") && argi + 1 < argc) {
			solve_diff = strtoul(argv[++argi], NULL, 0);
			have_solve = 1;
		} else if (!strcmp(argv[argi], "--base") && argi + 1 < argc)
			solve_base = strtoull(argv[++argi], NULL, 0);
		else if (!strcmp(argv[argi], "--count") && argi + 1 < argc)
			solve_count = strtoull(argv[++argi], NULL, 0);
		else if (!strcmp(argv[argi], "--clear") && argi + 1 < argc)
			clear_va = strtoull(argv[++argi], NULL, 0);
		else if (!strcmp(argv[argi], "-v"))
			verbose = 1;
		else {
			fprintf(stderr, "usage: %s [--dump DIR] [--upto N] "
				"[--bench N] [--solve DIFF] [--base B] [--count C] "
				"[--clear VA] [--poke VA:OFF:VAL] [-v]\n", argv[0]);
			return 2;
		}
	}

	subs = calloc(MAX_SUBS, sizeof(*subs));
	parse_manifest(subs, &nsubs);
	if (!nsubs)
		return 1;
	if (!upto || upto > nsubs)
		upto = nsubs;
	printf("capture: %u submissions, replaying %u\n", nsubs, upto);

	fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		die("open render node");

	if (ioctl(fd, DRM_IOCTL_I915_GEM_VM_CREATE, &vm) < 0)
		die("VM_CREATE");
	sp.base.name = I915_CONTEXT_CREATE_EXT_SETPARAM;
	sp.param.param = I915_CONTEXT_PARAM_VM;
	sp.param.value = vm.vm_id;
	cc.flags = I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS;
	cc.extensions = (uintptr_t)&sp;
	if (ioctl(fd, DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT, &cc) < 0)
		die("CONTEXT_CREATE_EXT");
	ctx = cc.ctx_id;
	printf("vm %u, context %u\n", vm.vm_id, ctx);

	/*
	 * One object per distinct virtual address: later submissions refer to
	 * the same objects, and pinning two objects at one address would fail.
	 * The first occurrence supplies the contents (the dumps of the same
	 * address are identical apart from buffers the driver keeps rewriting).
	 */
	{
		struct uniq {
			uint64_t va;
			uint32_t handle, size, manifest_handle;
			uint32_t *map;
			unsigned sub, idx;
		} *u = calloc(MAX_SUBS * MAX_OBJ, sizeof(*u));
		unsigned nu = 0;

		for (i = 0; i < upto; i++) {
			for (j = 0; j < subs[i].n; j++) {
				struct obj *o = &subs[i].objs[j];
				unsigned k;
				int found = 0;

				if (!o->handle)
					continue;
				for (k = 0; k < nu; k++)
					if (u[k].va == o->va) {
						found = 1;
						break;
					}
				if (found) {
					/* prefer the newest contents: batches grow */
					u[k].size = o->size;
					u[k].manifest_handle = o->handle;
					u[k].sub = i + 1;
					u[k].idx = j;
					continue;
				}
				u[nu].va = o->va;
				u[nu].size = o->size;
				u[nu].manifest_handle = o->handle;
				u[nu].sub = i + 1;
				u[nu].idx = j;
				nu++;
			}
		}

		printf("objects: %u distinct virtual addresses\n", nu);
		for (i = 0; i < nu; i++) {
			struct obj tmp = {
				.size = u[i].size,
				.va = u[i].va,
			};

			if (verbose)
				printf("  create 0x%llx (%u bytes) from sub%u idx%u\n",
				       (unsigned long long)u[i].va, u[i].size,
				       u[i].sub, u[i].idx);
			create_object(&tmp, u[i].sub, u[i].idx, u[i].manifest_handle);
			u[i].handle = tmp.handle;
			u[i].map = tmp.map;
			u[i].size = tmp.size;
			created[ncreated].va = u[i].va;
			created[ncreated].map = u[i].map;
			created[ncreated].size = u[i].size;
			ncreated++;
		}
		for (i = 0; i < upto; i++)
			for (j = 0; j < subs[i].n; j++) {
				unsigned k;

				for (k = 0; k < nu; k++)
					if (u[k].va == subs[i].objs[j].va) {
						subs[i].objs[j].handle = u[k].handle;
						subs[i].objs[j].map = u[k].map;
						subs[i].objs[j].size = u[k].size;
						break;
					}
			}
		free(u);
	}

	/*
	 * In solve mode, find the chosen submission's GPGPU walker and patch the
	 * argument block it points at:
	 *
	 *   payload + 0x30  message buffer pointer (u64)
	 *   payload + 0x38  results buffer pointer (u64)
	 *   payload + 0x40  base    (u32)
	 *   payload + 0x44  difficulty (u32)
	 *   payload + 0x48  count   (u32)
	 */
	if (have_solve) {
		struct sub *s0 = &subs[upto - 1];
		struct obj *batch = &s0->objs[s0->n - 1];
		uint32_t *blk = (uint32_t *)((char *)batch->map + s0->batch_start);
		uint32_t wi = 6;	/* walker is the 7th dword of a block */
		unsigned poff = 0;
		struct created *c, *msg, *res;
		uint32_t *pl;

		if (blk[wi] != 0x7105000d) {
			fprintf(stderr, "solve: no GPGPU walker at batch_start 0x%x "
				"(found 0x%08x)\n", s0->batch_start, blk[wi]);
			return 1;
		}
		c = find_low(blk[wi + 3], &poff);
		if (!c) {
			fprintf(stderr, "solve: payload 0x%x is not inside one of our objects\n",
				blk[wi + 3]);
			return 1;
		}
		pl = (uint32_t *)((char *)c->map + poff);
		msg = find_low(pl[0x30 / 4], NULL);
		res = find_low(pl[0x38 / 4], NULL);
		if (!msg || !res) {
			fprintf(stderr, "solve: message/results pointers not in our objects\n");
			return 1;
		}
		pl[0x40 / 4] = (uint32_t)solve_base;
		pl[0x44 / 4] = solve_diff;
		if (solve_count)
			pl[0x48 / 4] = (uint32_t)solve_count;
		printf("solve: payload 0x%llx+0x%x, msg 0x%llx, res 0x%llx, "
		       "base %llu, difficulty %u, count %u\n",
		       (unsigned long long)c->va, poff,
		       (unsigned long long)msg->va, (unsigned long long)res->va,
		       (unsigned long long)solve_base, solve_diff,
		       pl[0x48 / 4]);
		printf("tail ");
		for (i = 0; i < 44; i++)
			printf("%02x", ((unsigned char *)msg->map)[(i & ~3) + 3 - (i & 3)]);
		printf("\n");
		clear_va = res->va;
	}

	for (i = 0; i < npokes; i++) {
		struct created *c = find_created(pokes[i].va);

		if (!c || pokes[i].off + 4 > c->size) {
			fprintf(stderr, "poke: no object at 0x%llx or offset out of range\n",
				(unsigned long long)pokes[i].va);
			return 1;
		}
		*(uint32_t *)((char *)c->map + pokes[i].off) = pokes[i].val;
		printf("poke 0x%llx+0x%x = 0x%x\n", (unsigned long long)pokes[i].va,
		       pokes[i].off, pokes[i].val);
	}

	t0 = now_ms();
	for (i = 0; i < upto; i++)
		if (submit(&subs[i], ctx) < 0)
			return 1;
	t1 = now_ms();
	printf("replayed %u submissions in %.2f ms\n", upto, t1 - t0);

	if (clear_va) {
		struct created *c = find_created(clear_va);

		if (c) {
			memset(c->map, 0, c->size);
			printf("cleared object at 0x%llx\n", (unsigned long long)clear_va);
		}
	}

	if (have_solve) {
		/*
		 * Solve: one dispatch per repetition, results cleared each time so
		 * the hit count is this dispatch's, not a running total.
		 */
		struct sub *s0 = &subs[upto - 1];
		struct obj *batch = &s0->objs[s0->n - 1];
		uint32_t *blk = (uint32_t *)((char *)batch->map + s0->batch_start);
		unsigned poff = 0, k;
		struct created *c = find_low(blk[9], &poff);
		struct created *res = NULL;
		uint32_t total = 0;

		if (c) {
			uint32_t *pl = (uint32_t *)((char *)c->map + poff);

			res = find_low(pl[0x38 / 4], NULL);
		}
		if (!res) {
			fprintf(stderr, "solve: results buffer not found\n");
			return 1;
		}
		for (k = 0; k < bench; k++) {
			memset(res->map, 0, res->size);
			t0 = now_ms();
			if (submit(s0, ctx) < 0)
				return 1;
			t1 = now_ms();
			total = res->map[0];
			printf("dispatch %u: %u hits in %.3f ms (%.1f M hashes/s)\n",
			       k, total, t1 - t0,
			       nonces ? nonces / ((t1 - t0) * 1e3) : 0.0);
		}
		{
			uint32_t nhit = total < 8 ? total : 8, j;

			printf("hits %u\n", total);
			for (k = 0; k < nhit; k++) {
				printf("hit %u ", res->map[1 + k]);
				for (j = 0; j < 8; j++)
					printf("%08x", res->map[9 + k * 8 + j]);
				printf("\n");
			}
		}
	} else if (bench > 1) {
		/*
		 * Repeat the last dispatch (the prologue has already run, so the
		 * pipeline state is live).  Same nonces every time - this measures
		 * the dispatch, not a search.
		 */
		unsigned rep = upto - 1;

		t0 = now_ms();
		for (i = 1; i < bench; i++)
			if (submit(&subs[rep], ctx) < 0)
				return 1;
		t1 = now_ms();
		printf("dispatch: %u repeats of submission %u in %.2f ms = %.3f ms each\n",
		       bench - 1, rep + 1, t1 - t0, (t1 - t0) / (bench - 1));
		if (nonces)
			printf("  %.1f M hashes/s at %u nonces per dispatch\n",
			       (double)nonces * (bench - 1) / ((t1 - t0) * 1e3),
			       nonces);
	}

	/*
	 * Print what every small object holds now.  The candidate result buffer
	 * is the 4 KiB object at index 9 (NEO's `res`: hit count, hit nonces,
	 * then eight digest words); the other small objects are the kernel
	 * argument buffer and scratch space.
	 */
	{
		unsigned i, j, si = upto - 1;

		for (j = 0; j < subs[si].n; j++) {
			struct obj *o = &subs[si].objs[j];

			if (o->size != 4096 || !o->map)
				continue;
			printf("object idx %u va 0x%llx:", j, (unsigned long long)o->va);
			for (i = 0; i < 16; i++)
				printf(" %08x", o->map[i]);
			printf("\n");
			{
				unsigned k;
				uint32_t acc = 0;

				for (k = 9; k < 17; k++)
					acc |= o->map[k];
				/* a hit count is a small number; surface states are not */
				if (acc && o->map[0] <= 1024u) {
					printf("digest: total=%u nonce=%u ",
					       o->map[0], o->map[1]);
					for (k = 9; k < 17; k++)
						printf("%08x", o->map[k]);
					printf("\n");
				}
			}
		}
	}

	return 0;
}
