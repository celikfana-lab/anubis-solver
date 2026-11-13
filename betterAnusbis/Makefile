# betterAnusbis: build against the repository's own engine
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -pthread
LIBDIR  ?= ..
LDLIBS  ?= -L$(LIBDIR) -lanubis_solver -Wl,-rpath,$(abspath $(LIBDIR))

betterAnusbis: betterAnusbis.c $(LIBDIR)/libanubis_solver.so
	$(CC) $(CFLAGS) -I$(LIBDIR)/include -o $@ betterAnusbis.c $(LDLIBS)

../libanubis_solver.so:
	$(MAKE) -C .. libanubis_solver.so

clean:
	rm -f betterAnusbis

.PHONY: clean
