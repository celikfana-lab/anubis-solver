# betterAnusbis: the gate, linked against this repository's engine and OpenSSL.
#
#   make              # needs libanubis_solver.so (built by the parent Makefile)
#   make clean
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -pthread
LIBDIR  ?= ..
# our engine for verification, OpenSSL for the TLS listener and the TLS backend
LDLIBS  ?= -L$(LIBDIR) -lanubis_solver -Wl,-rpath,$(abspath $(LIBDIR)) -lssl -lcrypto

betterAnusbis: betterAnusbis.c $(LIBDIR)/libanubis_solver.so
	$(CC) $(CFLAGS) -I$(LIBDIR)/include -o $@ betterAnusbis.c $(LDLIBS)

$(LIBDIR)/libanubis_solver.so:
	$(MAKE) -C $(LIBDIR) libanubis_solver.so

clean:
	rm -f betterAnusbis

.PHONY: clean
