# HashX compiled to WAT, benchmarked, and demoed in a browser.
#
#   make            # generate the WAT from the vector program and assemble it
#   make bench      # node bench.mjs: our JIT vs the official Anubis modules
#   make serve      # http server for the demo (the browser cannot fetch file://)
#   make clean
REPO    ?= ..
HASHES  ?= 2000000
OFFICIAL ?= /media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm

all: hashx_jit.wasm demo/hashx_jit.wasm argon2_fill.wasm argon2_fill_simd.wasm argon2_fill_c.wasm sha256_pow.wasm

hashx_jit.wat: $(REPO)/tools/gen_hashx_wat.py $(REPO)/beyond/vectors/hx_vectors.hex
	python3 $(REPO)/tools/gen_hashx_wat.py --out wasm/hashx_jit.wat

hashx_jit.wasm: hashx_jit.wat
	wat2wasm hashx_jit.wat -o hashx_jit.wasm
	@ls -l hashx_jit.wasm

demo/hashx_jit.wasm: hashx_jit.wasm
	cp hashx_jit.wasm demo/hashx_jit.wasm

argon2_fill.wat: $(REPO)/tools/gen_argon2_wat.py
	python3 $(REPO)/tools/gen_argon2_wat.py --out wasm/argon2_fill.wat

# the recommended Argon2id kernel: C, -O3, no -msimd128 (measured slower)
# wasm-ld comes from the lld package; point WASMLD at it if it is not on PATH
# our sha256 PoW kernel: same ABI as the modules Anubis ships
sha256_pow.wasm: sha256_pow.c
	clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -Wl,--export-memory \
	      -Wl,--export=data_ptr -Wl,--export=set_data_length \
	      -Wl,--export=result_hash_ptr -Wl,--export=result_hash_size \
	      -Wl,--export=anubis_work -o sha256_pow.wasm sha256_pow.c
	@ls -l sha256_pow.wasm

# needs a running Anubis: anubis -bind 127.0.0.1:8923 \
#   -target http://127.0.0.1:8001 -policy-fname policy.yaml \
#   -cookie-secure=false -use-remote-address
live: sha256_pow.wasm
	node live-test.mjs --url $${ANUBIS_URL:-http://127.0.0.1:8923/} --runs $${RUNS:-8}

argon2_fill_c.wasm: compiler/fill.c
	clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -Wl,--export=fill_block \
	      -Wl,--export-memory -o argon2_fill_c.wasm compiler/fill.c
	@ls -l argon2_fill_c.wasm

argon2_fill_simd.wat: $(REPO)/tools/gen_argon2_wat_simd.py
	python3 $(REPO)/tools/gen_argon2_wat_simd.py --out wasm/argon2_fill_simd.wat

argon2_fill_simd.wasm: argon2_fill_simd.wat
	wat2wasm argon2_fill_simd.wat -o argon2_fill_simd.wasm
	@ls -l argon2_fill_simd.wasm

argon2_fill.wasm: argon2_fill.wat
	wat2wasm argon2_fill.wat -o argon2_fill.wasm
	@ls -l argon2_fill.wasm

# the fill_block vectors come from compiling the vendored C reference itself
fill_vectors.txt: ref_fill_vectors.c
	cc -O1 -pthread -I$(REPO)/third_party/argon2 -I$(REPO)/third_party/argon2/blake2 \
	   -o /tmp/fillref ref_fill_vectors.c \
	   $(REPO)/third_party/argon2/blake2/blake2b.c $(REPO)/third_party/argon2/thread.c
	/tmp/fillref > fill_vectors.txt

vectors: fill_vectors.txt

a2i: all
	node verify-a2i.mjs
	node bench-a2i.mjs
	node bench-memory.mjs
	node bench-threads.mjs --hashes 6

# the same fill_block compiled from Rust, for the WAT-vs-compiler question
compiler/%.wasm: compiler/fill.rs
	rustc --target wasm32-unknown-unknown --crate-type=cdylib -C opt-level=3 \
	      -C panic=abort -C lto=yes $* -o $@ fill.rs 2>/dev/null || \
	rustc --target wasm32-unknown-unknown --crate-type=cdylib -C opt-level=3 \
	      -C panic=abort -C lto=yes -o $@ compiler/fill.rs

compiler: compiler/fill_scalar.wasm compiler/fill_simd.wasm

compare: all
	@rustc --target wasm32-unknown-unknown --crate-type=cdylib -C opt-level=3 -C panic=abort -C lto=yes -o compiler/fill_scalar.wasm compiler/fill.rs
	@rustc --target wasm32-unknown-unknown --crate-type=cdylib -C opt-level=3 -C panic=abort -C lto=yes -C target-feature=+simd128 -o compiler/fill_simd.wasm compiler/fill.rs
	node bench-compiler.mjs

bench: all
	node bench.mjs --hashes $(HASHES) --official $(OFFICIAL)
	node verify.mjs

serve: all
	@echo "demo: http://127.0.0.1:8933/demo/"
	python3 -m http.server 8933 --bind 127.0.0.1

clean:
	rm -f compiler/fill_*.wasm hashx_jit.wasm hashx_jit.wat demo/hashx_jit.wasm \
	      argon2_fill.wasm argon2_fill.wat argon2_fill_simd.wasm argon2_fill_simd.wat \
	      argon2_fill_c.wasm

.PHONY: all bench a2i vectors compare live serve clean
