# anubis.R — solve Anubis proof-of-work challenges from R.
#
#   source("anubis.R")
#   r <- anubis_solve_nibbles("demo-challenge", 3)
#   r$nonce; r$hash
#
# The work is done by libanubis_solver.so through a small .Call shim
# (src/anubis_r.c), because R's base .C() interface throws away the C return
# value and every function in this library signals success through it.
#
# Build once, from the repository root (`make`), then from bindings/r:
#   make            # builds anubisR.so
#   Rscript test.R  # or: R --vanilla -f test.R
#
# Library location: ANUBIS_LIB, else the repository root above this file.

`%||%` <- function(a, b) if (is.null(a) || is.na(a) || identical(a, "")) b else a

# a string stays a string (its UTF-8 bytes); a raw vector stays raw bytes
as_data <- function(x) {
    if (is.raw(x)) return(x)
    if (is.character(x) && length(x) == 1) return(x)
    stop("expected a single string or a raw vector", call. = FALSE)
}

.anubis_dir <- local({
    # directory of this file, when sourced
    of <- tryCatch(sys.frame(1)$ofile, error = function(e) NULL)
    if (is.null(of)) getwd() else dirname(of)
})

.anubis_lib_candidates <- function() {
    env <- Sys.getenv("ANUBIS_LIB", "")
    c(
        if (nzchar(env)) env,
        file.path(.anubis_dir, "..", "..", "libanubis_solver.so"),
        file.path(.anubis_dir, "..", "..", "libanubis_solver.dylib"),
        file.path(getwd(), "libanubis_solver.so")
    )
}

.anubis_load <- function() {
    shim <- file.path(.anubis_dir, "anubisR.so")
    if (!file.exists(shim)) {
        stop("anubisR.so not built. Run `make` in bindings/r first.", call. = FALSE)
    }
    # load the target library first so the shim's symbols resolve even when the
    # build did not bake in an rpath
    found <- Filter(file.exists, .anubis_lib_candidates())
    if (length(found) == 0) {
        stop("libanubis_solver not found. Build it with `make` at the repository root, ",
             "or set ANUBIS_LIB.", call. = FALSE)
    }
    if (!is.loaded("R_init_anubisR")) {
        dyn.load(found[[1]], local = FALSE, now = TRUE)
        dyn.load(shim, local = FALSE, now = TRUE)
    }
    invisible(found[[1]])
}

.anubis_call <- function(name, ...) {
    .anubis_load()
    .Call(name, ...)
}

# ---------------------------------------------------------------- conditions

.anubis_error <- function(status, what) {
    msg <- switch(as.character(status),
        "1" = "invalid argument",
        "2" = "exhausted the nonce or time budget",
        "3" = "internal error",
        paste0("unknown return code ", status)
    )
    cls <- switch(as.character(status),
        "1" = c("anubis_argument_error", "anubis_error", "error", "condition"),
        "2" = c("anubis_unsolved", "anubis_error", "error", "condition"),
        c("anubis_internal_error", "anubis_error", "error", "condition")
    )
    stop(structure(class = cls, list(message = paste0(what, ": ", msg), call = NULL,
                                     status = status)))
}

.anubis_result <- function(r, what) {
    if (r$status != 0L) .anubis_error(r$status, what)
    list(nonce = r$nonce, hash = r$hash, ms = r$ms)
}

# ------------------------------------------------------------- introspection

anubis_version         <- function() .anubis_call("anubis_r_version")
anubis_gpu_info        <- function() .anubis_call("anubis_r_gpu_info")
anubis_default_threads <- function() .anubis_call("anubis_r_default_threads")
anubis_affinity_info   <- function() .anubis_call("anubis_r_affinity_info")
anubis_batch_width     <- function() .anubis_call("anubis_r_batch_width")
anubis_set_gpu_verify  <- function(enable) invisible(.anubis_call("anubis_r_set_gpu_verify", as.logical(enable)))
anubis_gpu_verify      <- function() .anubis_call("anubis_r_gpu_verify")

anubis_info <- function() {
    list(
        version    = anubis_version(),
        gpu        = anubis_gpu_info(),
        threads    = anubis_default_threads(),
        affinity   = anubis_affinity_info(),
        batchWidth = anubis_batch_width(),
        gpuVerify  = anubis_gpu_verify()
    )
}

# --------------------------------------------------------------- sha256 utils

anubis_sha256_hex <- function(data) .anubis_call("anubis_r_sha256_hex", as_data(data))

anubis_sha256_midstate <- function(data) .anubis_call("anubis_r_sha256_midstate", as_data(data))

# ------------------------------------------------------------------- solving

anubis_solve_nibbles <- function(challenge, difficulty, threads = 0L,
                                 max_nonce = -1, budget_ms = 0) {
    .anubis_result(
        .anubis_call("anubis_r_solve_nibbles", as.character(challenge)[1],
                     as.integer(difficulty), as.integer(threads),
                     as.numeric(max_nonce), as.numeric(budget_ms)),
        "anubis_solve_nibbles")
}

anubis_solve_sha256 <- function(challenge_hex, difficulty, threads = 0L, budget_ms = 0) {
    .anubis_result(
        .anubis_call("anubis_r_solve_bits", as.character(challenge_hex)[1],
                     as.integer(difficulty), as.integer(threads), as.numeric(budget_ms)),
        "anubis_solve_bits")
}

anubis_solve_argon2id <- function(challenge_hex, difficulty, threads = 0L, budget_ms = 0) {
    .anubis_result(
        .anubis_call("anubis_r_solve_argon2id", as.character(challenge_hex)[1],
                     as.integer(difficulty), as.integer(threads), as.numeric(budget_ms)),
        "anubis_solve_argon2id")
}

anubis_solve_hashx <- function(challenge_hex, difficulty, threads = 0L, budget_ms = 0) {
    .anubis_result(
        .anubis_call("anubis_r_solve_hashx", as.character(challenge_hex)[1],
                     as.integer(difficulty), as.integer(threads), as.numeric(budget_ms)),
        "anubis_solve_hashx")
}

anubis_solve <- function(algorithm, challenge, difficulty, threads = 0L, budget_ms = 0) {
    switch(algorithm,
        fast = ,
        slow = anubis_solve_nibbles(challenge, difficulty, threads, budget_ms = budget_ms),
        sha256 = ,
        `wasm-sha256` = anubis_solve_sha256(challenge, difficulty, threads, budget_ms),
        argon2id = anubis_solve_argon2id(challenge, difficulty, threads, budget_ms),
        hashx = anubis_solve_hashx(challenge, difficulty, threads, budget_ms),
        stop("unknown algorithm: ", algorithm, call. = FALSE)
    )
}

# ----------------------------------------------------------------- verifying

.anubis_verdict <- function(r) list(ok = r$ok, hash = r$hash)

anubis_verify_nibbles <- function(challenge, nonce, difficulty) {
    .anubis_verdict(.anubis_call("anubis_r_verify_nibbles", as.character(challenge)[1],
                                 as.numeric(nonce), as.integer(difficulty)))
}

anubis_verify_sha256 <- function(challenge_hex, nonce, difficulty) {
    .anubis_verdict(.anubis_call("anubis_r_verify_bits", as.character(challenge_hex)[1],
                                 as.numeric(nonce), as.integer(difficulty)))
}

anubis_verify_argon2id <- function(challenge_hex, nonce, difficulty) {
    .anubis_verdict(.anubis_call("anubis_r_verify_argon2id", as.character(challenge_hex)[1],
                                 as.numeric(nonce), as.integer(difficulty)))
}

anubis_verify_hashx <- function(challenge_hex, nonce, difficulty) {
    .anubis_verdict(.anubis_call("anubis_r_verify_hashx", as.character(challenge_hex)[1],
                                 as.numeric(nonce), as.integer(difficulty)))
}

anubis_verify <- function(algorithm, challenge, nonce, difficulty) {
    switch(algorithm,
        fast = , slow = anubis_verify_nibbles(challenge, nonce, difficulty),
        sha256 = , `wasm-sha256` = anubis_verify_sha256(challenge, nonce, difficulty),
        argon2id = anubis_verify_argon2id(challenge, nonce, difficulty),
        hashx = anubis_verify_hashx(challenge, nonce, difficulty),
        stop("unknown algorithm: ", algorithm, call. = FALSE)
    )
}
