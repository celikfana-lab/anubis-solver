# HashX compiled to WAT, benchmarked, and demoed in a browser.
#
#   make            # generate the WAT from the vector program and assemble it
#   make bench      # node bench.mjs: our JIT vs the official Anubis modules
#   make serve      # http server for the demo (the browser cannot fetch file://)
#   make clean
REPO    ?= ..
HASHES  ?= 2000000
OFFICIAL ?= /media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm

all: hashx_jit.wasm demo/hashx_jit.wasm

hashx_jit.wat: $(REPO)/tools/gen_hashx_wat.py $(REPO)/beyond/vectors/hx_vectors.hex
	python3 $(REPO)/tools/gen_hashx_wat.py --out wasm/hashx_jit.wat

hashx_jit.wasm: hashx_jit.wat
	wat2wasm hashx_jit.wat -o hashx_jit.wasm
	@ls -l hashx_jit.wasm

demo/hashx_jit.wasm: hashx_jit.wasm
	cp hashx_jit.wasm demo/hashx_jit.wasm

bench: all
	node bench.mjs --hashes $(HASHES) --official $(OFFICIAL)

serve: all
	@echo "demo: http://127.0.0.1:8933/demo/"
	python3 -m http.server 8933 --bind 127.0.0.1

clean:
	rm -f hashx_jit.wasm hashx_jit.wat demo/hashx_jit.wasm

.PHONY: all bench serve clean
