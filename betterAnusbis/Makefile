# betterAnusbis: the gate, linked against this repository's engine and OpenSSL.
#
#   make              # needs libanubis_solver.so (built by the parent Makefile)
#   make clean
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -pthread -std=gnu17
LIBDIR  ?= ..
# Our engine for verification, OpenSSL for the TLS listener and the TLS backend.
# The runpath is $ORIGIN, not the build directory: a released binary and its
# .so sit next to each other, and a binary that points at /home/someone/build
# is not an artifact, it is a souvenir.
# $ORIGIN covers a release directory (both files side by side); $ORIGIN/.. is
# the build tree, where the library lives one level up.
RPATH   ?= '$$ORIGIN:$$ORIGIN/..'
LDLIBS  ?= -L$(LIBDIR) -lanubis_solver -Wl,-rpath,$(RPATH) -lssl -lcrypto

# HTTP/2 and HTTP/3 are optional at build time, and the binary always keeps
# working without them: a gate that cannot be built because a distribution
# packaged nghttp2 differently is worse than one that only speaks HTTP/1.1.
# pkg-config is the whole detection story for nghttp2. nghttp3 is rarer, so it
# is looked for in the usual place, in $(NGHTTP3_PREFIX), and in third_party/.
NGHTTP2_CFLAGS ?= $(shell pkg-config --cflags libnghttp2 2>/dev/null)
NGHTTP2_LIBS   ?= $(shell pkg-config --libs libnghttp2 2>/dev/null)
HTTP_CFLAGS :=
HTTP_LIBS   :=
ifneq ($(strip $(NGHTTP2_LIBS)),)
HTTP_CFLAGS += -DHAVE_NGHTTP2 $(NGHTTP2_CFLAGS)
HTTP_LIBS   += $(NGHTTP2_LIBS)
endif

NGHTTP3_PREFIX ?= $(or $(shell pkg-config --variable=prefix libnghttp3 2>/dev/null),../third_party/nghttp3)
NGHTTP3_CFLAGS ?= $(wildcard $(NGHTTP3_PREFIX)/include/nghttp3/nghttp3.h)
NGHTTP3_LIB    ?= $(firstword $(wildcard $(NGHTTP3_PREFIX)/lib/libnghttp3.a $(NGHTTP3_PREFIX)/lib/libnghttp3.so) $(shell pkg-config --libs libnghttp3 2>/dev/null))
# nghttp3 is not enough: the HTTP/3 code calls OpenSSL's QUIC API, which is
# 3.5 and later. third_party/nghttp3 ships with the tree, so a distribution
# with an older OpenSSL (Kaggle's image is 3.0) would otherwise fail on
# <openssl/quic.h> and take the whole gate down with it. Ask the compiler;
# -include keeps the probe free of make's '#' comment rules.
OPENSSL_QUIC_H := $(shell $(CC) -E -x c -include openssl/quic.h - </dev/null >/dev/null 2>&1 && echo yes)
ifneq ($(strip $(NGHTTP3_CFLAGS)),)
ifneq ($(strip $(NGHTTP3_LIB)),)
ifneq ($(strip $(OPENSSL_QUIC_H)),)
HTTP_CFLAGS += -DHAVE_NGHTTP3 -I$(NGHTTP3_PREFIX)/include
HTTP_LIBS   += $(NGHTTP3_LIB)
endif
endif
endif

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
web/meatrider_pow.wasm: $(WASM)/meatrider_pow.wasm
	cp $< $@
web/tensor_pow.wasm: $(WASM)/tensor_pow.wasm
	cp -f $< $@

wasm-kernels: web/argon2id_pow.wasm web/hashx_pow.wasm web/sha256_pow_batch.wasm \
              web/tensor_pow.wasm web/meatrider_pow.wasm

betterAnusbis: betterAnusbis.c $(LIBDIR)/libanubis_solver.so
	$(CC) $(CFLAGS) $(HTTP_CFLAGS) -I$(LIBDIR)/include -o $@ betterAnusbis.c $(LDLIBS) $(HTTP_LIBS)

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

# HTTP/1.1, HTTP/2 and HTTP/3 on both the listener and the backend hop. Skips
# the cases whose tooling (curl --http2, aioquic, python h2) is not installed.
test-http23: betterAnusbis
	python3 tests_http23.py -v

# The Valkey store against the test file's in-process RESP2 mock (or a real
# valkey-server/redis-server when one is on PATH).
test-valkey: betterAnusbis
	python3 tests_valkey.py

# The S3 store against the test file's in-process S3 mock (independent SigV4
# verification); no AWS account or network is needed.
test-s3: betterAnusbis
	python3 tests_s3.py

# The page's pure-JavaScript solvers: SHA-256 against node:crypto, plus the
# sha256 (both nonce byte orders, with and without WebAssembly) and fast/slow
# paths through the extracted page script. No browser, no gate.
test-js:
	node tests_js_sha256.mjs
	node tests_js_hashx.mjs
	node tests_js_argon2id.mjs
	node tests_js_tensor.mjs

clean:
	rm -f betterAnusbis

.PHONY: clean wasm-kernels slow test-parity test-http23 test-valkey test-s3 test-js
