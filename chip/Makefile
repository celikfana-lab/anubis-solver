IVERILOG ?= iverilog
VVP      ?= vvp
YOSYS    ?= yosys

.PHONY: all sim clean synth

all: sim

sim: tb_sha256 tb_pow tb_argon2_fill tb_lpddr6 tb_blake2b tb_blake2b_stream tb_h_prime
	$(VVP) tb_sha256
	$(VVP) tb_pow
	$(VVP) tb_argon2_fill
	$(VVP) tb_lpddr6
	$(VVP) tb_blake2b
	$(VVP) tb_blake2b_stream
	$(VVP) tb_h_prime

blake2b: tb_blake2b
	$(VVP) tb_blake2b

stream: tb_blake2b_stream
	$(VVP) tb_blake2b_stream

hprime: tb_h_prime
	$(VVP) tb_h_prime

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

tb_argon2_fill: tb_argon2_fill.v argon2_fill.v
	python3 gen_argon_vectors.py
	$(IVERILOG) -g2012 -o $@ tb_argon2_fill.v argon2_fill.v

synth:
	$(YOSYS) -p "read_verilog -sv sha256_core.v anubis_pow.v; synth -top sha256_core; stat"

clean:
	rm -f tb_sha256 tb_pow tb_argon2_fill tb_blake2b tb_blake2b_stream tb_h_prime tb_lpddr6 *.vcd prev.hex ref.hex dst.hex expected.hex b2_vectors.hex hp_vectors.hex
