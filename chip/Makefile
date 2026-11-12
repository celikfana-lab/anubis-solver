IVERILOG ?= iverilog
VVP      ?= vvp
YOSYS    ?= yosys

.PHONY: all sim clean synth

all: sim

sim: tb_sha256 tb_pow
	$(VVP) tb_sha256
	$(VVP) tb_pow

pow: tb_pow
	$(VVP) tb_pow

tb_sha256: tb_sha256.v sha256_core.v
	$(IVERILOG) -g2012 -o $@ $^

tb_pow: tb_pow.v anubis_pow.v sha256_core.v
	$(IVERILOG) -g2012 -o $@ $^

synth:
	$(YOSYS) -p "read_verilog -sv sha256_core.v anubis_pow.v; synth -top sha256_core; stat"

clean:
	rm -f tb_sha256 tb_pow *.vcd
