# chip/Makefile — simulate the SHA-256 and Argon2id proof-of-work datapath.
#
# Run everything from this directory: the testbenches read their vectors from
# vectors/ with relative paths, and binaries go to build/.

IVERILOG  ?= iverilog
VVP       ?= vvp
YOSYS     ?= yosys
VERILATOR ?= verilator
NPROC     ?= $(shell nproc)
# Verilator 5.020 aborts ("locked Thread Pool") with very high -j on the big
# model, so the build parallelism is capped separately from the machine size.
VLJOBS    ?= 16

DIFF ?= 4      # `make solve` difficulty (argon2id)
MAXN ?= 32     # `make solve` nonces to try
HDIFF ?= 8     # `make solve-hashx` difficulty
HMAXN ?= 256   # `make solve-hashx` nonces to try

B   := build
PY  := python3
V   := $(VVP)

# ---- sources --------------------------------------------------------------
SHA   := rtl/sha256/sha256_core.v
POW   := $(SHA) rtl/sha256/anubis_pow.v
MEM   := rtl/mem/lpddr6_model.v rtl/mem/lpddr6_if.v
B2    := rtl/blake2b/blake2b_core.v rtl/blake2b/blake2b_stream.v
HASH  := $(B2) rtl/blake2b/h0.v rtl/blake2b/h_prime.v
ARGON := rtl/argon2/argon2_fill.v rtl/argon2/argon2_index.v rtl/argon2/argon2_addr.v
HASHX := rtl/hashx/sipround.v rtl/hashx/hashx_prf.v rtl/hashx/hashx_exec.v \
         rtl/hashx/hashx_top.v
HASHX_REF := ../src/hashx
ENGINE := rtl/argon2/argon2_engine.v $(ARGON) $(HASH)

# ---- testbenches ----------------------------------------------------------
# name: dependencies | vector generator
TBS := tb_sha256 tb_pow tb_lpddr6 tb_argon2_fill tb_blake2b tb_blake2b_stream \
       tb_h_prime tb_h0 tb_argon2_addr tb_argon2_index tb_argon2_engine \
       tb_hashx

.PHONY: all sim $(TBS) pow argon blake2b stream hprime h0 addr index engine \
        hashx solve solve-hashx vectors vl64 vlreal synth clean
.DEFAULT_GOAL := all

all: sim

sim: $(addprefix $(B)/,$(TBS))
	@for t in $(TBS); do echo "== $$t"; $(V) $(B)/$$t || exit 1; done

$(B):
	@mkdir -p $(B)

$(B)/tb_sha256: tb/tb_sha256.v $(SHA) | $(B)
	$(IVERILOG) -g2012 -o $@ $^

$(B)/tb_pow: tb/tb_pow.v $(POW) | $(B)
	$(IVERILOG) -g2012 -o $@ $^

$(B)/tb_lpddr6: tb/tb_lpddr6.v $(MEM) | $(B)
	$(IVERILOG) -g2012 -o $@ $^

$(B)/tb_argon2_fill: tb/tb_argon2_fill.v rtl/argon2/argon2_fill.v | $(B)
	$(PY) tools/gen_argon_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_argon2_fill.v rtl/argon2/argon2_fill.v

$(B)/tb_blake2b: tb/tb_blake2b.v rtl/blake2b/blake2b_core.v | $(B)
	$(IVERILOG) -g2012 -o $@ tb/tb_blake2b.v rtl/blake2b/blake2b_core.v

$(B)/tb_blake2b_stream: tb/tb_blake2b_stream.v $(B2) | $(B)
	$(PY) tools/gen_blake2b_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_blake2b_stream.v $(B2)

$(B)/tb_h_prime: tb/tb_h_prime.v rtl/blake2b/h_prime.v $(B2) | $(B)
	$(PY) tools/gen_hprime_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_h_prime.v rtl/blake2b/h_prime.v $(B2)

$(B)/tb_h0: tb/tb_h0.v rtl/blake2b/h0.v $(B2) | $(B)
	$(PY) tools/gen_h0_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_h0.v rtl/blake2b/h0.v $(B2)

$(B)/tb_argon2_addr: tb/tb_argon2_addr.v rtl/argon2/argon2_addr.v rtl/argon2/argon2_fill.v | $(B)
	$(PY) tools/gen_addr_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_argon2_addr.v rtl/argon2/argon2_addr.v rtl/argon2/argon2_fill.v

$(B)/tb_argon2_index: tb/tb_argon2_index.v rtl/argon2/argon2_index.v | $(B)
	$(PY) tools/gen_index_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_argon2_index.v rtl/argon2/argon2_index.v

$(B)/tb_argon2_engine: tb/tb_argon2_engine.v $(ENGINE) | $(B)
	$(PY) tools/gen_engine_vectors.py >/dev/null
	$(IVERILOG) -g2012 -o $@ tb/tb_argon2_engine.v $(ENGINE)

# HashX: the program is generated in software by the C reference, which keeps
# this an interpreter plus a fixed table - the same split the GPU backends use.
$(B)/gen_hashx_vectors: tools/gen_hashx_vectors.c $(HASHX_REF)/hashx.c | $(B)
	$(CC) -O2 -I $(HASHX_REF) -o $@ tools/gen_hashx_vectors.c $(HASHX_REF)/hashx.c

$(B)/tb_hashx: tb/tb_hashx.v $(HASHX) $(B)/gen_hashx_vectors | $(B)
	$(B)/gen_hashx_vectors vectors/hx_vectors.hex
	$(IVERILOG) -g2012 -o $@ tb/tb_hashx.v $(HASHX)

$(B)/tb_hashx_solve: tb/tb_hashx_solve.v $(HASHX) $(B)/gen_hashx_vectors | $(B)
	$(B)/gen_hashx_vectors vectors/hx_vectors.hex
	$(IVERILOG) -g2012 -Ptb_hashx_solve.DIFF=$(HDIFF) -Ptb_hashx_solve.MAXN=$(HMAXN) \
	  -o $@ tb/tb_hashx_solve.v $(HASHX)

solve-hashx: $(B)/tb_hashx_solve
	$(V) $(B)/tb_hashx_solve

# The on-chip nonce search. M_COST is a tb parameter; leave it at 64 (or the
# engine's 43k cycles per hash become 10M) and use `make vlreal` for the real
# parameters.
solve: $(B)/tb_anubis_solve
	$(V) $(B)/tb_anubis_solve

$(B)/tb_anubis_solve: tb/tb_anubis_solve.v $(ENGINE) | $(B)
	$(IVERILOG) -g2012 -Ptb_anubis_solve.DIFF=$(DIFF) -Ptb_anubis_solve.MAXN=$(MAXN) \
	  -o $@ tb/tb_anubis_solve.v $(ENGINE)

# ---- shortcuts ------------------------------------------------------------
pow:     ; $(MAKE) --no-print-directory $(B)/tb_pow && $(V) $(B)/tb_pow
argon:   ; $(MAKE) --no-print-directory $(B)/tb_argon2_fill && $(V) $(B)/tb_argon2_fill
blake2b: ; $(MAKE) --no-print-directory $(B)/tb_blake2b && $(V) $(B)/tb_blake2b
stream:  ; $(MAKE) --no-print-directory $(B)/tb_blake2b_stream && $(V) $(B)/tb_blake2b_stream
hprime:  ; $(MAKE) --no-print-directory $(B)/tb_h_prime && $(V) $(B)/tb_h_prime
h0:      ; $(MAKE) --no-print-directory $(B)/tb_h0 && $(V) $(B)/tb_h0
addr:    ; $(MAKE) --no-print-directory $(B)/tb_argon2_addr && $(V) $(B)/tb_argon2_addr
index:   ; $(MAKE) --no-print-directory $(B)/tb_argon2_index && $(V) $(B)/tb_argon2_index
engine:  ; $(MAKE) --no-print-directory $(B)/tb_argon2_engine && $(V) $(B)/tb_argon2_engine
hashx:   ; $(MAKE) --no-print-directory $(B)/tb_hashx && $(V) $(B)/tb_hashx

vectors: $(B)/gen_hashx_vectors
	@for g in tools/gen_*.py; do echo "== $$g"; $(PY) $$g; done
	@$(B)/gen_hashx_vectors vectors/hx_vectors.hex

# ---- Verilator ------------------------------------------------------------
# Compiling the RTL to C++ is ~1000x faster than Icarus here: 0.17 s instead of
# 174 s for 19 nonces, and 3.9 s instead of ~36 min for one real hash.
# the C++ file must be absolute: Verilator's generated makefile runs inside the
# Mdir and otherwise cannot find a nested source path
SIM_MAIN := $(abspath sim/sim_main.cpp)
VL = $(VERILATOR) -cc --exe --build -j $(VLJOBS) -O3 -Wno-fatal \
     -CFLAGS "-O3 -march=native" --Mdir $(B)/obj_$@ --top-module sim_top \
     -o $@ sim/sim_top.v $(ENGINE) $(SIM_MAIN)

vl64: $(ENGINE) sim/sim_top.v sim/sim_main.cpp | $(B)
	$(VL) -GM_COST=64 -GDIFF=4
	$(B)/obj_vl64/vl64 0 32 32 0

vlreal: $(ENGINE) sim/sim_top.v sim/sim_main.cpp | $(B)
	$(VL) -GM_COST=19456 -GDIFF=5
	$(B)/obj_vlreal/vlreal 25 1 32 0

# ---- misc -----------------------------------------------------------------
synth:
	$(YOSYS) -p "read_verilog -sv $(SHA) rtl/sha256/anubis_pow.v; synth -top sha256_core; stat"

clean:
	rm -rf $(B) vectors/*.hex~ vectors/prev.hex vectors/ref.hex vectors/dst.hex \
	       vectors/expected.hex vectors/b2_vectors.hex vectors/hp_vectors.hex \
	       vectors/h0_vectors.hex vectors/addr_vectors.hex vectors/index_vectors.hex \
	       vectors/engine_vectors.hex vectors/engine_pw.hex vectors/solve_nonce.txt \
	       vectors/hx_vectors.hex
	-find . -name '__pycache__' -prune -exec rm -rf {} +
