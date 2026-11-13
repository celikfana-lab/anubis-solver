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

# This checkout is a laptop. The heavy simulation, sweeps and Verilator builds
# run on a 56-core box instead: `make remote-sim`, `make remote-mpipe`, ...
HOST       ?= airobots@192.168.1.15
REMOTE_DIR ?= ~/anubis-solver
RSYNC      ?= rsync -a --delete --exclude build --exclude .git --exclude mascot
REMOTE_JOBS ?= 16

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
PERIPH := rtl/periph/uart_tx.v rtl/periph/uart_log.v rtl/periph/axil_regs.v
# the whole card: engine array + eight HBM3e stacks + BAR0 + UART
CARD := rtl/top/anubis_argon2_card.v rtl/argon2/argon2_mpipe.v \
        rtl/mem/hbm3e_mem.v rtl/mem/hbm3_model.v \
        rtl/periph/uart_tx.v rtl/periph/uart_log.v rtl/periph/axil_regs.v
HASHX_REF := ../src/hashx
ENGINE := rtl/argon2/argon2_engine.v $(ARGON) $(HASH)

# ---- testbenches ----------------------------------------------------------
# name: dependencies | vector generator
TBS := tb_sha256 tb_pow tb_lpddr6 tb_argon2_fill tb_blake2b tb_blake2b_stream \
       tb_h_prime tb_h0 tb_argon2_addr tb_argon2_index tb_argon2_engine \
       tb_hashx tb_uart tb_axil tb_argon2_card

  .PHONY: all sim $(TBS) run-all pow argon blake2b stream hprime h0 addr index engine \
        hashx solve solve-hashx mpipe vectors vl64 vlreal synth area clean \
        sync hbm3e-capacity hbm3e-mpipe card-argon2 card-argon2-max
.DEFAULT_GOAL := all

all: sim

# one phony run target per testbench, so `make -jN sim` runs them concurrently
sim: $(addprefix run-,$(TBS))

run-%: $(B)/%
	@echo "== $*"
	@$(V) $(B)/$*

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

$(B)/tb_uart: tb/tb_uart.v $(PERIPH) | $(B)
	$(IVERILOG) -g2012 -o $@ tb/tb_uart.v rtl/periph/uart_log.v rtl/periph/uart_tx.v

$(B)/tb_axil: tb/tb_axil.v rtl/periph/axil_regs.v | $(B)
	$(IVERILOG) -g2012 -o $@ tb/tb_axil.v rtl/periph/axil_regs.v

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

# ---- architecture studies --------------------------------------------------
# The memory-architecture model: NENG engines x KCTX hashes in flight against
# an HBM3 link. The fill_block work is a cycle counter here, so this measures
# whether the memory system keeps the engines busy - the thing that decides
# hashes/s once the ARGON block itself is fixed.
$(B)/tb_mpipe: tb/tb_mpipe.v rtl/argon2/argon2_mpipe.v rtl/mem/hbm3_model.v | $(B)
	$(IVERILOG) -g2012 -o $@ tb/tb_mpipe.v rtl/argon2/argon2_mpipe.v rtl/mem/hbm3_model.v

mpipe: $(B)/tb_mpipe
	$(V) $(B)/tb_mpipe

# ---- HBM3e x8 --------------------------------------------------------------
# Eight HBM3e stacks behind rtl/mem/hbm3e_mem.v: 1228 B/cycle per stack
# (1228.8 at 1 GHz rounded down 0.07%) => 9824 B/cycle = 9.82 TB/s aggregate.
# `hbm3e-capacity` measures the subsystem alone (and the client-port limit);
# `hbm3e-mpipe` is the engine sweep. Deliberately not in TBS/sim: these are
# architecture studies, and the sweep rebuilds per engine count.
HBM3E     := rtl/mem/hbm3e_mem.v rtl/mem/hbm3_model.v
HBM3E_BW  ?= 1228
HBM3E_LAT ?= 350
HBM3E_EFF ?= 100
# THE MAXIMUM THIS MEMORY CAN FEED. 9,824 B/cycle of HBM3e is 2.74 blocks/cycle
# at 3,584 B per block, and with 3 contexts per engine a block costs the
# datapath's own 133 cycles, so 2.74 x 133 = 365 engines saturate all eight
# stacks and a 366th buys nothing. (At 2 contexts the latency floor is 175
# cycles/block and the same link needs 484 engines for the same hashes/s.)
# A full run of this default takes ~15 minutes of Icarus; drop MP_NENG to
# 240 or so while iterating.
MP_NENG   ?= 365
MP_KCTX   ?= 3
MP_CYC    ?= 133
MP_NSTACK ?= 8
# 3 lanes: 9,824 / 3,584 = 2.74 requests per cycle are needed, and one lane is
# 3,584 B/cycle, so one lane would use 36% of the stacks.
MP_NPORT  ?= 3
MP_NRESP  ?= 3
MP_TARGET ?= 10000
MP_WARMUP ?= 500

$(B)/tb_hbm3e_capacity: tb/tb_hbm3e_x8.v $(HBM3E) | $(B)
	$(IVERILOG) -g2012 -s tb_hbm3e_capacity \
	  -Ptb_hbm3e_capacity.BW=$(HBM3E_BW) -Ptb_hbm3e_capacity.LAT=$(HBM3E_LAT) \
	  -Ptb_hbm3e_capacity.EFF=$(HBM3E_EFF) -o $@ tb/tb_hbm3e_x8.v $(HBM3E)

$(B)/tb_hbm3e_mpipe: tb/tb_hbm3e_x8.v $(HBM3E) rtl/argon2/argon2_mpipe.v | $(B)
	$(IVERILOG) -g2012 -s tb_hbm3e_mpipe \
	  -Ptb_hbm3e_mpipe.NENG=$(MP_NENG) -Ptb_hbm3e_mpipe.KCTX=$(MP_KCTX) \
	  -Ptb_hbm3e_mpipe.CYC_BLOCK=$(MP_CYC) -Ptb_hbm3e_mpipe.NSTACK=$(MP_NSTACK) \
	  -Ptb_hbm3e_mpipe.BW=$(HBM3E_BW) -Ptb_hbm3e_mpipe.LAT=$(HBM3E_LAT) \
	  -Ptb_hbm3e_mpipe.EFF=$(HBM3E_EFF) \
	  -Ptb_hbm3e_mpipe.NPORT=$(MP_NPORT) -Ptb_hbm3e_mpipe.NRESP=$(MP_NRESP) \
	  -Ptb_hbm3e_mpipe.TARGET=$(MP_TARGET) -Ptb_hbm3e_mpipe.WARMUP=$(MP_WARMUP) \
	  -o $@ tb/tb_hbm3e_x8.v $(HBM3E) rtl/argon2/argon2_mpipe.v

hbm3e-capacity: $(B)/tb_hbm3e_capacity
	$(V) $(B)/tb_hbm3e_capacity

# sweep: rebuild per point with e.g.
#   make -B hbm3e-mpipe MP_NENG=236 MP_CYC=260 MP_NSTACK=8
hbm3e-mpipe: $(B)/tb_hbm3e_mpipe
	$(V) $(B)/tb_hbm3e_mpipe

# ---- the card: 365 engines x 3 contexts behind eight HBM3e stacks -----------
# This is the design point from SPEED.md as one synthesizable top. The fast
# default test only checks the wiring; the real configuration is the -max target.
CARD_NENG ?= 365
CARD_KCTX ?= 3

$(B)/tb_argon2_card: tb/tb_argon2_card.v $(CARD) | $(B)
	$(IVERILOG) -g2012 -o $@ tb/tb_argon2_card.v $(CARD)

card-argon2: $(B)/tb_argon2_card
	$(V) $(B)/tb_argon2_card

$(B)/tb_argon2_card_max: tb/tb_argon2_card.v $(CARD) | $(B)
	$(IVERILOG) -g2012 -Ptb_argon2_card.NENG=$(CARD_NENG) \
	  -Ptb_argon2_card.KCTX=$(CARD_KCTX) \
	  -Ptb_argon2_card.LAT=350 -Ptb_argon2_card.CYC=133 \
	  -Ptb_argon2_card.WARMUP=600 -Ptb_argon2_card.WINDOW=400 \
	  -o $@ tb/tb_argon2_card.v $(CARD)

# the real 365-engine chip; several minutes of Icarus
card-argon2-max: $(B)/tb_argon2_card_max
	$(V) $(B)/tb_argon2_card_max

# ---- Verilator ------------------------------------------------------------
# Compiling the RTL to C++ is ~1000x faster than Icarus here: 0.17 s instead of
# 174 s for 19 nonces, and 2.2 s instead of ~18 min for one real hash (the
# write-back change that halved cycles/hash also halved this).
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
# Generic-cell counts from yosys, for comparing core sizes. These are not
# standard cells: a wide mux maps to roughly 1.5 gates per cell, and a real
# synthesis run would beat the mux network with a banked register file.
AREA_TOPS := rtl/sha256/sha256_core.v rtl/argon2/argon2_fill.v \
             rtl/hashx/hashx_exec.v rtl/mem/lpddr6_if.v

area:
	@for f in $(AREA_TOPS); do \
	  t=$$(basename $$f .v); printf "%-16s " $$t; \
	  $(YOSYS) -p "read_verilog -sv $$f; synth -top $$t -flatten; stat" 2>/dev/null \
	    | awk '/Number of cells:/{c=$$NF} /Number of wire bits:/{w=$$NF} END{printf "cells=%-8s wires=%s\n", c, w}'; \
	done

synth:
	$(YOSYS) -p "read_verilog -sv $(SHA) rtl/sha256/anubis_pow.v; synth -top sha256_core; stat"

# ---- run on the build server ----------------------------------------------
# the repo root, not just chip/: the HashX vectors are generated against
# ../src/hashx, so a chip-only copy cannot build on the far side
sync:
	$(RSYNC) $(CURDIR)/../ $(HOST):$(REMOTE_DIR)/

remote-%: sync
	ssh $(HOST) 'cd $(REMOTE_DIR)/chip && make -j$(REMOTE_JOBS) $*'

clean:
	rm -rf $(B) vectors/*.hex~ vectors/prev.hex vectors/ref.hex vectors/dst.hex \
	       vectors/expected.hex vectors/b2_vectors.hex vectors/hp_vectors.hex \
	       vectors/h0_vectors.hex vectors/addr_vectors.hex vectors/index_vectors.hex \
	       vectors/engine_vectors.hex vectors/engine_pw.hex vectors/solve_nonce.txt \
	       vectors/hx_vectors.hex
	-find . -name '__pycache__' -prune -exec rm -rf {} +
