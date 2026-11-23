# SHA-256 in pure Scratch.
#
#   make            the 4-bit-limb project (small file, readable lists)
#   make byte       the 8-bit-limb project (4x throughput, 65k-entry lists)
#   make test       both projects against hashlib
#   make bench      the per-statement cost of the interpreter

PY      ?= python3
NODE    ?= node
# where scratch-vm and jszip are installed (npm i scratch-vm jszip)
NODE_PATH ?= /tmp/node_modules
export NODE_PATH

all: build/sha256.sb3

build/sha256.sb3: gen_sha256.py tools/sb3.py
	$(PY) gen_sha256.py

build/sha256_b8.sb3: gen_sha256.py tools/sb3.py
	$(PY) gen_sha256.py --limb 8 --out build/sha256_b8.sb3

byte: build/sha256_b8.sb3

run: build/sha256.sb3
	$(NODE) tools/run_sb3.mjs build/sha256.sb3 '[97,98,99]'

profile: build/sha256.sb3
	$(NODE) tools/profile_sb3.mjs build/sha256.sb3

test: build/sha256.sb3
	$(PY) tools/verify_sha256.py

test-byte: build/sha256_b8.sb3
	$(PY) tools/verify_sha256.py --sb3 build/sha256_b8.sb3

test-all: test test-byte

bench:
	$(PY) tools/bench_ops.py

clean:
	rm -rf build

.PHONY: all byte run profile test test-byte test-all bench clean
