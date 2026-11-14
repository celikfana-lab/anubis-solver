# betterAnusbis: the gate, linked against this repository's engine and OpenSSL.
#
#   make              # needs libanubis_solver.so (built by the parent Makefile)
#   make clean
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -pthread
LIBDIR  ?= ..
# our engine for verification, OpenSSL for the TLS listener and the TLS backend
LDLIBS  ?= -L$(LIBDIR) -lanubis_solver -Wl,-rpath,$(abspath $(LIBDIR)) -lssl -lcrypto

# the first rule in a makefile is its default goal, and the wasm copies below
# must not become it
.DEFAULT_GOAL := betterAnusbis

# the browser kernels, copied from wasm/ where they are built and verified
WASM    ?= ../wasm
web/argon2id_pow.wasm: $(WASM)/argon2id_pow.wasm
	cp -f $< $@
web/hashx_pow.wasm: $(WASM)/hashx_pow.wasm
	cp -f $< $@
web/sha256_pow_batch.wasm: $(WASM)/sha256_pow_batch.wasm
	cp -f $< $@

wasm-kernels: web/argon2id_pow.wasm web/hashx_pow.wasm web/sha256_pow_batch.wasm

betterAnusbis: betterAnusbis.c $(LIBDIR)/libanubis_solver.so
	$(CC) $(CFLAGS) -I$(LIBDIR)/include -o $@ betterAnusbis.c $(LDLIBS)

$(LIBDIR)/libanubis_solver.so:
	$(MAKE) -C $(LIBDIR) libanubis_solver.so

# The demo the progress bar exists for: hashx at a hostile difficulty, solved in
# the browser. It needs a backend to protect, so pass one:
#   make slow TARGET=http://127.0.0.1:8002 DIFFICULTY=28
TARGET  ?= http://127.0.0.1:3000
DIFFICULTY ?= 28
slow: betterAnusbis wasm-kernels
	./betterAnusbis --listen 127.0.0.1:4949 --target $(TARGET) \
	    --algorithm hashx --difficulty $(DIFFICULTY)

# The flags taken from cmd/anubis, checked on the wire. Starts its own backend
# and its own gate, so it needs nothing running.
test-parity: betterAnusbis
	python3 test_parity.py

clean:
	rm -f betterAnusbis

.PHONY: clean wasm-kernels slow test-parity
