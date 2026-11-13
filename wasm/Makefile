# HashX compiled to WAT, benchmarked, and demoed in a browser.
#
#   make            # generate the WAT from the vector program and assemble it
#   make bench      # node bench.mjs: our JIT vs the official Anubis modules
#   make serve      # http server for the demo (the browser cannot fetch file://)
#   make clean
REPO    ?= ..
HASHES  ?= 2000000
OFFICIAL ?= /media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm

all: hashx_jit.wasm demo/hashx_jit.wasm argon2_fill.wasm

hashx_jit.wat: $(REPO)/tools/gen_hashx_wat.py $(REPO)/beyond/vectors/hx_vectors.hex
	python3 $(REPO)/tools/gen_hashx_wat.py --out wasm/hashx_jit.wat

hashx_jit.wasm: hashx_jit.wat
	wat2wasm hashx_jit.wat -o hashx_jit.wasm
	@ls -l hashx_jit.wasm

demo/hashx_jit.wasm: hashx_jit.wasm
	cp hashx_jit.wasm demo/hashx_jit.wasm

argon2_fill.wat: $(REPO)/tools/gen_argon2_wat.py
	python3 $(REPO)/tools/gen_argon2_wat.py --out wasm/argon2_fill.wat

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
	rm -f compiler/fill_*.wasm hashx_jit.wasm hashx_jit.wat demo/hashx_jit.wasm argon2_fill.wasm argon2_fill.wat

.PHONY: all bench a2i vectors compare serve clean
