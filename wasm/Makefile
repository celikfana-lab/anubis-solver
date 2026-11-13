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
all: argon2id_pow.wasm hashx_pow.wasm

# Two flags bite the Argon2id module, and both were measured before they were
# believed:
#
#   -ffreestanding or -mcpu=mvp  turn off the builtin memcpy, so the 1 KiB block
#     copies inside fill_block become calls to the byte-at-a-time shim in
#     wasm_string.c instead of inline loads and stores. That alone is 2.0x
#     slower (1661 -> 3380 ns per block) and it is how the first shipped
#     argon2id_pow.wasm was built.
#   -msimd128                    costs 8-15%: LLVM auto-vectorises the BLAKE2
#     round into something slower than the scalar code.
#
# The other half of the module's speed is argon2_fill_fast.c: ref.c expands each
# round over the whole 1 KiB block, whereas gathering a round into a 16-word
# local with constant indices keeps it in registers (2030 -> 1661 ns/block).
ARGON2_SRC = $(REPO)/third_party/argon2
argon2id_pow.wasm: argon2id_pow.c argon2_fill_fast.c wasm_arena.h wasm_string.c \
                   $(ARGON2_SRC)/argon2.c $(ARGON2_SRC)/core.c \
                   $(ARGON2_SRC)/blake2/blake2b.c $(ARGON2_SRC)/encoding.c
	clang --target=wasm32 -O3 -DARGON2_NO_THREADS -nostdlib -Wl,--no-entry \
	      -I$(ARGON2_SRC) -I$(ARGON2_SRC)/blake2 -I. -Iinclude \
	      -Wl,--export-memory -Wl,--export=data_ptr -Wl,--export=set_data_length \
	      -Wl,--export=result_hash_ptr -Wl,--export=result_hash_size \
	      -Wl,--export=anubis_work -o argon2id_pow.wasm \
	      argon2id_pow.c argon2_fill_fast.c $(ARGON2_SRC)/argon2.c \
	      $(ARGON2_SRC)/core.c $(ARGON2_SRC)/blake2/blake2b.c \
	      $(ARGON2_SRC)/encoding.c wasm_string.c
	@ls -l argon2id_pow.wasm

# HASHX_NO_INT128: hashx.c uses __int128 for its 64x64->128 multiplies, which
# wasm has no instruction for and a -nostdlib build has no compiler-rt to supply
# (the link fails on __multi3). The portable 32-bit-half version is the same
# arithmetic and measures the same; see AGENTS.md notes on __multi3.
hashx_pow.wasm: hashx_pow.c wasm_arena.h wasm_string.c $(REPO)/src/hashx/hashx.c
	clang --target=wasm32 -O3 -DHASHX_NO_INT128 -nostdlib -Wl,--no-entry \
	      -I. -Iinclude -I$(REPO)/src/hashx -I$(REPO)/include \
	      -Wl,--export-memory -Wl,--export=data_ptr -Wl,--export=set_data_length \
	      -Wl,--export=result_hash_ptr -Wl,--export=result_hash_size \
	      -Wl,--export=anubis_work -o hashx_pow.wasm \
	      hashx_pow.c $(REPO)/src/hashx/hashx.c wasm_string.c
	@ls -l hashx_pow.wasm

# the module-level regression test: ten random challenges at difficulties 1..5,
# each digest offered to the official Anubis module, which must accept it
verify-module: argon2id_pow.wasm hashx_pow.wasm
	node verify-a2i-module.mjs
	node verify-hashx-module.mjs

# the runtime HashX compiler: derive the program, emit wasm bytes, check them
# against hashx_pow.wasm (the interpreter) and against the committed
# hashx_jit.wasm. Also fails if the copy inlined in betterAnusbis.c has drifted
# from hashx_jit.mjs.
verify-jit: hashx_jit.mjs verify-jit.mjs
	node verify-jit.mjs

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
