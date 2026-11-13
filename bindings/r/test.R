# Exercises every R binding against the real library.
#   R --vanilla -f test.R          (or Rscript test.R)
#
# Needs anubisR.so (`make` in this directory) and libanubis_solver.so (`make` at
# the repository root).

here <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) NULL)
if (is.null(here) || !nzchar(here)) here <- getwd()
setwd(here)
source("anubis.R")

pass <- 0L
fail <- 0L
check <- function(name, fn) {
    ok <- tryCatch({ fn(); TRUE }, error = function(e) {
        cat("  FAIL ", name, ": ", conditionMessage(e), "\n", sep = "")
        FALSE
    })
    if (ok) { cat("  ok   ", name, "\n", sep = ""); pass <<- pass + 1L }
    else fail <<- fail + 1L
}
eq <- function(got, want, what = "") {
    if (!identical(got, want)) stop(what, " got ", format(got), ", want ", format(want))
}

HEX <- "00112233445566778899aabbccddeeff"
digest_re <- "^[0-9a-f]{64}$"

i <- anubis_info()
cat("version ", i$version, " | gpu ", i$gpu %||% "none", " | threads ", i$threads,
    " | affinity ", i$affinity %||% "", " | batch ", i$batchWidth, "\n\n", sep = "")

check("info looks sane", function() {
    if (!grepl("^[0-9]+\\.[0-9]+\\.[0-9]+$", i$version)) stop("version ", i$version)
    if (i$threads < 1) stop("threads ", i$threads)
})

check("sha256_hex matches a known digest", function()
    eq(anubis_sha256_hex("abc"),
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))

check("sha256_hex of a raw vector hashes the bytes, not their repr", function() {
    # 0x61 0x62 0x63 as raw bytes is the same input as "abc"
    eq(anubis_sha256_hex(as.raw(c(0x61, 0x62, 0x63))),
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
})

check("sha256_midstate returns 8 words and rejects 63 bytes", function() {
    w <- anubis_sha256_midstate(strrep("a", 64))
    eq(length(w), 8L)
    err <- tryCatch({ anubis_sha256_midstate(strrep("a", 63)); NULL }, error = function(e) e)
    if (is.null(err)) stop("63 bytes should have been rejected")
})

check("nibbles: solve and verify", function() {
    r <- anubis_solve_nibbles("demo-challenge", 3)
    if (!grepl(digest_re, r$hash)) stop("hash ", r$hash)
    v <- anubis_verify_nibbles("demo-challenge", r$nonce, 3)
    if (!v$ok) stop("nonce ", r$nonce, " did not verify")
    eq(v$hash, r$hash)
})

check("nibbles: a wrong nonce does not verify", function() {
    if (anubis_verify_nibbles("demo-challenge", 999999, 3)$ok) stop("a wrong nonce verified")
})

check("sha256 (wasm): solve and verify", function() {
    r <- anubis_solve_sha256(HEX, 8)
    v <- anubis_verify_sha256(HEX, r$nonce, 8)
    if (!v$ok) stop("did not verify")
    eq(v$hash, r$hash)
})

check("argon2id: solve and verify", function() {
    r <- anubis_solve_argon2id(HEX, 4)
    if (!anubis_verify_argon2id(HEX, r$nonce, 4)$ok) stop("did not verify")
})

check("hashx: solve and verify", function() {
    r <- anubis_solve_hashx(HEX, 4)
    if (!anubis_verify_hashx(HEX, r$nonce, 4)$ok) stop("did not verify")
})

check("generic dispatcher routes every algorithm", function() {
    for (case in list(list("fast", "demo-challenge", 2L),
                      list("sha256", HEX, 4L),
                      list("argon2id", HEX, 4L),
                      list("hashx", HEX, 4L))) {
        r <- anubis_solve(case[[1]], case[[2]], case[[3]])
        if (!grepl(digest_re, r$hash)) stop(case[[1]], ": hash ", r$hash)
    }
})

check("an unknown algorithm is an error", function() {
    err <- tryCatch({ anubis_solve("md5", "x", 1); NULL }, error = function(e) e)
    if (is.null(err)) stop("should have raised")
})

check("an unsolvable budget raises an anubis_unsolved condition", function() {
    err <- tryCatch({ anubis_solve_nibbles("demo-challenge", 64, budget_ms = 1); NULL },
                    error = function(e) e)
    if (is.null(err)) stop("should have raised")
    if (!inherits(err, "anubis_unsolved")) stop("class was ", paste(class(err), collapse = "/"))
    if (err$status != 2L) stop("status ", err$status)
})

check("malformed hex raises anubis_argument_error", function() {
    err <- tryCatch({ anubis_solve_sha256("not-hex", 4); NULL }, error = function(e) e)
    if (is.null(err)) stop("should have raised")
    if (!inherits(err, "anubis_argument_error")) stop("class was ", paste(class(err), collapse = "/"))
})

check("an independently computed digest matches the solver", function() {
    r <- anubis_solve_sha256(HEX, 4)
    raw_ch <- raw(0)
    for (k in seq(1, nchar(HEX), by = 2)) {
        raw_ch <- c(raw_ch, as.raw(strtoi(substr(HEX, k, k + 1), 16L)))
    }
    # the core picks the nonce byte order from the challenge's last byte
    n <- r$nonce
    be <- as.raw(c(bitwAnd(bitwShiftR(n, 24), 255), bitwAnd(bitwShiftR(n, 16), 255),
                   bitwAnd(bitwShiftR(n, 8), 255), bitwAnd(n, 255)))
    le <- rev(be)
    nb <- if (as.integer(raw_ch[length(raw_ch)]) >= 128) le else be
    eq(anubis_sha256_hex(c(raw_ch, nb)), r$hash, "digest")
})

cat("\n", pass, " passed, ", fail, " failed\n", sep = "")
if (fail > 0) quit(status = 1)
