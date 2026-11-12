IVERILOG ?= iverilog
VVP      ?= vvp
DIFF     ?= 4
MAXN     ?= 32
YOSYS    ?= yosys

.PHONY: all sim clean synth

all: sim

sim: tb_sha256 tb_pow tb_argon2_fill tb_lpddr6 tb_blake2b tb_blake2b_stream \
     tb_h_prime tb_h0 tb_argon2_addr tb_argon2_index tb_argon2_engine
	$(VVP) tb_sha256
	$(VVP) tb_pow
	$(VVP) tb_argon2_fill
	$(VVP) tb_lpddr6
	$(VVP) tb_blake2b
	$(VVP) tb_blake2b_stream
	$(VVP) tb_h_prime
	$(VVP) tb_h0
	$(VVP) tb_argon2_addr
	$(VVP) tb_argon2_index
	$(VVP) tb_argon2_engine

blake2b: tb_blake2b
	$(VVP) tb_blake2b

stream: tb_blake2b_stream
	$(VVP) tb_blake2b_stream

hprime: tb_h_prime
	$(VVP) tb_h_prime

h0: tb_h0
	$(VVP) tb_h0
	$(VVP) tb_h0

argon: tb_argon2_fill
	$(VVP) tb_argon2_fill

pow: tb_pow
	$(VVP) tb_pow

tb_sha256: tb_sha256.v sha256_core.v
	$(IVERILOG) -g2012 -o $@ $^

tb_pow: tb_pow.v anubis_pow.v sha256_core.v
	$(IVERILOG) -g2012 -o $@ $^

tb_lpddr6: tb_lpddr6.v lpddr6_if.v lpddr6_model.v
	$(IVERILOG) -g2012 -o $@ $^

tb_blake2b: tb_blake2b.v blake2b_core.v
	$(IVERILOG) -g2012 -o $@ $^

tb_blake2b_stream: tb_blake2b_stream.v blake2b_stream.v blake2b_core.v
	python3 gen_blake2b_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_blake2b_stream.v blake2b_stream.v blake2b_core.v

tb_h_prime: tb_h_prime.v h_prime.v blake2b_stream.v blake2b_core.v
	python3 gen_hprime_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_h_prime.v h_prime.v blake2b_stream.v blake2b_core.v

tb_h0: tb_h0.v h0.v blake2b_stream.v blake2b_core.v
	python3 gen_h0_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_h0.v h0.v blake2b_stream.v blake2b_core.v

tb_argon2_addr: tb_argon2_addr.v argon2_addr.v argon2_fill.v gen_argon_vectors.py
	python3 gen_addr_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_argon2_addr.v argon2_addr.v argon2_fill.v

tb_argon2_index: tb_argon2_index.v argon2_index.v
	python3 gen_index_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_argon2_index.v argon2_index.v

ARGON_SRC = argon2_index.v argon2_addr.v argon2_fill.v h_prime.v h0.v \
            blake2b_stream.v blake2b_core.v

tb_argon2_engine: tb_argon2_engine.v argon2_engine.v $(ARGON_SRC)
	python3 gen_engine_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_argon2_engine.v argon2_engine.v $(ARGON_SRC)

# the on-chip nonce search; M_COST=64 keeps a whole search to a few minutes
solve: tb_anubis_solve
	$(VVP) tb_anubis_solve

tb_anubis_solve: tb_anubis_solve.v argon2_engine.v $(ARGON_SRC)
	$(IVERILOG) -g2012 -Ptb_anubis_solve.DIFF=$(DIFF) -Ptb_anubis_solve.MAXN=$(MAXN) \
	  -o $@ tb_anubis_solve.v argon2_engine.v $(ARGON_SRC)

tb_argon2_fill: tb_argon2_fill.v argon2_fill.v
	python3 gen_argon_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_argon2_fill.v argon2_fill.v

synth:
	$(YOSYS) -p "read_verilog -sv sha256_core.v anubis_pow.v; synth -top sha256_core; stat"

clean:
	rm -f tb_sha256 tb_pow tb_argon2_fill tb_blake2b tb_blake2b_stream tb_h_prime tb_h0 tb_argon2_addr tb_argon2_engine tb_argon2_index tb_lpddr6 *.vcd prev.hex ref.hex dst.hex expected.hex b2_vectors.hex hp_vectors.hex h0_vectors.hex addr_vectors.hex index_vectors.hex engine_vectors.hex engine_pw.hex
