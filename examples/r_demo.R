# R demo: solve an Anubis challenge through libanubis_solver.
#
#   cd bindings/r && make            # builds anubisR.so (once)
#   R --vanilla -f examples/r_demo.R  # from the repository root
#
# anubis.R finds libanubis_solver.so at ANUBIS_LIB, else the repository root.

script_dir <- function() {
    a <- commandArgs(trailingOnly = FALSE)
    f <- sub("^--file=", "", a[grep("^--file=", a)])
    if (length(f) == 1 && nzchar(f)) return(dirname(normalizePath(f)))
    of <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) NULL)
    if (!is.null(of) && nzchar(of)) return(of)
    getwd()
}
here <- script_dir()
# runnable from the repository root or from examples/
lib_candidates <- c(file.path(here, "..", "bindings", "r", "anubis.R"),
                    file.path(here, "bindings", "r", "anubis.R"))
lib_file <- lib_candidates[file.exists(lib_candidates)][1]
if (is.na(lib_file)) stop("cannot find bindings/r/anubis.R; run from the repo root")
source(lib_file)

none <- function(x) if (is.null(x) || is.na(x)) "(none)" else x

i <- anubis_info()
cat(sprintf("libanubis_solver %s  gpu %s  threads %d  batch %d\n",
            i$version, none(i$gpu), i$threads, i$batchWidth))

# fast / slow: SHA-256 over challenge || decimal nonce, leading zero nibbles
nib <- anubis_solve_nibbles("demo-challenge", 3)
cat(sprintf("nibbles   nonce %.0f  %s  %.3f ms\n", nib$nonce, nib$hash, nib$ms))

v <- anubis_verify_nibbles("demo-challenge", nib$nonce, 3)
cat(sprintf("verify    %s  %s\n",
            if (v$ok) "ok" else "FAILED",
            if (identical(v$hash, nib$hash)) "same digest" else "DIFFERENT digest"))

# sha256 / argon2id / hashx: leading zero bits, hex challenge
hex <- "00112233445566778899aabbccddeeff"
bits <- anubis_solve("sha256", hex, 8)
cat(sprintf("sha256    nonce %.0f  %s\n", bits$nonce, bits$hash))
cat(sprintf("verify    %s\n",
            if (anubis_verify("sha256", hex, bits$nonce, 8)$ok) "ok" else "FAILED"))

# the library's own SHA-256, to cross-check a digest independently
cat(sprintf('sha256("abc") = %s\n', anubis_sha256_hex("abc")))

# an exhausted budget is an R condition, not a crash
tryCatch(anubis_solve_nibbles("demo-challenge", 64, budget_ms = 1),
         anubis_unsolved = function(e) cat("unsolvable budget -> anubis_unsolved condition\n"))
