# Builds the .Call shim for the R bindings.
#
#   make                 # uses `R CMD SHLIB` (any normal R install)
#   R --vanilla -f test.R
#
# If R was unpacked somewhere without the `R CMD` wrapper, compile directly and
# point at its headers and libR:
#
#   make direct R_INCLUDE=/path/to/R/include R_LIB=/path/to/R/lib
REPO      ?= ../..
R_CMD     ?= R
CC        ?= cc
R_INCLUDE ?= $(shell command -v $(R_CMD) >/dev/null 2>&1 && echo $$($(R_CMD) RHOME)/include)

# the shim needs libanubis_solver at link time and an rpath so it is found later
RPATH    := $(abspath $(REPO))
PKG_CPPFLAGS := -I$(REPO)/include
PKG_LIBS     := -L$(RPATH) -lanubis_solver -Wl,-rpath,$(RPATH)

all: anubisR.so

anubisR.so: src/anubis_r.c $(REPO)/libanubis_solver.so
	PKG_CPPFLAGS="$(PKG_CPPFLAGS)" PKG_LIBS="$(PKG_LIBS)" \
		$(R_CMD) CMD SHLIB -o anubisR.so src/anubis_r.c

direct: src/anubis_r.c
	$(CC) -shared -fPIC -I$(R_INCLUDE) -I$(REPO)/include src/anubis_r.c \
		-o anubisR.so $(PKG_LIBS) $(R_LIB_LDFLAGS)

clean:
	rm -f anubisR.so src/*.o

.PHONY: all direct clean
