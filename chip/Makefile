IVERILOG ?= iverilog
VVP      ?= vvp
YOSYS    ?= yosys

.PHONY: all sim clean synth

all: sim

sim: tb_sha256 tb_pow tb_argon2_fill tb_lpddr6
	$(VVP) tb_sha256
	$(VVP) tb_pow
	$(VVP) tb_argon2_fill
	$(VVP) tb_lpddr6

# BLAKE2b core is WIP (wrong digest, see README), run it explicitly.
blake2b: tb_blake2b
	$(VVP) tb_blake2b

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

tb_argon2_fill: tb_argon2_fill.v argon2_fill.v
	python3 gen_argon_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_argon2_fill.v argon2_fill.v

synth:
	$(YOSYS) -p "read_verilog -sv sha256_core.v anubis_pow.v; synth -top sha256_core; stat"

clean:
	rm -f tb_sha256 tb_pow tb_argon2_fill tb_blake2b tb_lpddr6 *.vcd prev.hex ref.hex dst.hex expected.hex
