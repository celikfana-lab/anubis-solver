//! Rust bindings for `libanubis_solver` — solve Anubis proof-of-work challenges.
//!
//! ```no_run
//! let r = anubis_solver::solve_nibbles("demo-challenge", 3, Default::default())?;
//! println!("nonce {} -> {} in {:.1} ms", r.nonce, r.hash, r.millis);
//! # Ok::<(), anubis_solver::Error>(())
//! ```
//!
//! A thin, hand-written FFI layer over the C ABI in `include/anubis-solver.h`:
//! no `bindgen`, no build-time code generation, no dependencies at all. The
//! proof of work is done by the C engine (AVX2 / AVX-512 / SHA-NI kernels, or a
//! GPU backend if one is configured), not by Rust.
//!
//! Build the library first, from the repository root:
//!
//! ```text
//! make
//! ```
//!
//! The crate's `build.rs` points the linker at the repository root and bakes in
//! an rpath, so `cargo test` works with no `LD_LIBRARY_PATH`. Point it elsewhere
//! with `ANUBIS_LIB_DIR=/path/to/dir cargo build`.
//!
//! # Algorithms
//!
//! | Anubis name | function | difficulty unit |
//! |---|---|---|
//! | `fast`, `slow` | [`solve_nibbles`] | leading zero hex nibbles |
//! | `sha256`, `wasm-sha256` | [`solve_sha256`] | leading zero bits |
//! | `argon2id` | [`solve_argon2id`] | leading zero bits |
//! | `hashx` | [`solve_hashx`] | leading zero bits |
//!
//! [`solve`] dispatches on the name Anubis puts in the challenge page.

#![deny(missing_docs)]
#![warn(clippy::all)]

use std::ffi::{c_char, c_double, c_int, CStr, CString};
use std::fmt;

/// Status codes, mirroring `anubis-solver.h`.
pub const OK: i32 = 0;
/// A bad argument: malformed hex challenge or a difficulty out of range.
pub const ERR_ARG: i32 = 1;
/// The nonce or time budget was exhausted.
pub const ERR_UNSOLVED: i32 = 2;
/// A backend or library failure.
pub const ERR_INTERNAL: i32 = 3;

/// Everything that can go wrong. `Unauthorized` never appears here — this crate
/// only wraps the solver, not the HTTP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// [`ERR_ARG`]: malformed challenge or an out-of-range difficulty.
    Argument,
    /// [`ERR_UNSOLVED`]: the nonce or time budget ran out.
    Unsolved,
    /// [`ERR_INTERNAL`]: a backend or library failure.
    Internal,
    /// A return code this crate does not know.
    Unknown(i32),
    /// The challenge string contained a NUL byte.
    InteriorNul,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Argument => write!(f, "anubis: invalid argument"),
            Error::Unsolved => write!(f, "anubis: exhausted the nonce or time budget"),
            Error::Internal => write!(f, "anubis: internal error"),
            Error::Unknown(code) => write!(f, "anubis: unknown return code {code}"),
            Error::InteriorNul => write!(f, "anubis: the challenge contains a NUL byte"),
        }
    }
}

impl std::error::Error for Error {}

impl From<i32> for Error {
    fn from(rc: i32) -> Self {
        match rc {
            ERR_ARG => Error::Argument,
            ERR_UNSOLVED => Error::Unsolved,
            ERR_INTERNAL => Error::Internal,
            other => Error::Unknown(other),
        }
    }
}

/// The answer to one challenge.
#[derive(Debug, Clone, PartialEq)]
pub struct Solution {
    /// The nonce that satisfies the difficulty.
    pub nonce: u64,
    /// Lowercase hex digest of the winning input.
    pub hash: String,
    /// How long the search took, in milliseconds.
    pub millis: f64,
}

/// Optional knobs. The default is "pick threads yourself, no limits".
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Worker threads; `0` means the library default.
    pub threads: i32,
    /// Upper bound on the nonce search; `<= 0` means no limit.
    pub max_nonce: i64,
    /// Time budget in milliseconds; `<= 0` means no limit.
    pub budget_ms: f64,
}

impl Default for Options {
    fn default() -> Self {
        Options { threads: 0, max_nonce: -1, budget_ms: 0.0 }
    }
}

/// Library and machine facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Library version, e.g. `"1.2.1"`.
    pub version: String,
    /// Active GPU backend, if any.
    pub gpu: Option<String>,
    /// The library's idea of a sensible worker count.
    pub threads: i32,
    /// Human-readable CPU affinity, if the platform has one.
    pub affinity: Option<String>,
    /// SHA-256 batch width: 16 (AVX-512), 8 (AVX2), 0 (scalar).
    pub batch_width: i32,
    /// Whether GPU hits are re-checked on the CPU.
    pub gpu_verify: bool,
}

/// An Anubis algorithm, by the name the challenge page uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-256 over `challenge || decimal nonce`, leading zero nibbles.
    Fast,
    /// Same primitive, different client implementation.
    Slow,
    /// SHA-256 over raw challenge bytes `|| u32 nonce`, leading zero bits.
    Sha256,
    /// Argon2id, leading zero bits.
    Argon2id,
    /// HashX, leading zero bits.
    Hashx,
}

impl Algorithm {
    /// Parse the name Anubis puts in the challenge payload.
    pub fn parse(name: &str) -> Option<Algorithm> {
        match name {
            "fast" => Some(Algorithm::Fast),
            "slow" => Some(Algorithm::Slow),
            "sha256" | "wasm-sha256" => Some(Algorithm::Sha256),
            "argon2id" => Some(Algorithm::Argon2id),
            "hashx" => Some(Algorithm::Hashx),
            _ => None,
        }
    }
}

/* ------------------------------------------------------------------ FFI */

#[allow(missing_docs)]
mod ffi {
    use super::*;

    extern "C" {
        pub fn anubis_solver_version() -> *const c_char;
        pub fn anubis_gpu_info() -> *const c_char;
        pub fn anubis_default_threads() -> c_int;
        pub fn anubis_cpu_affinity_info() -> *const c_char;
        pub fn anubis_batch_width() -> c_int;
        pub fn anubis_set_gpu_verify(enable: c_int);
        pub fn anubis_gpu_verify() -> c_int;

        pub fn anubis_sha256_hex(data: *const c_char, len: usize, out_hex: *mut c_char) -> c_int;
        pub fn anubis_sha256_midstate(
            data: *const c_char,
            len: usize,
            out_words: *mut u32,
        ) -> c_int;

        pub fn anubis_solve_nibbles(
            challenge: *const c_char,
            difficulty: c_int,
            threads: c_int,
            max_nonce: i64,
            budget_ms: c_double,
            out_nonce: *mut u64,
            out_hex: *mut c_char,
            out_ms: *mut c_double,
        ) -> c_int;

        pub fn anubis_solve_bits(
            challenge_hex: *const c_char,
            difficulty: c_int,
            threads: c_int,
            budget_ms: c_double,
            out_nonce: *mut u32,
            out_hex: *mut c_char,
            out_ms: *mut c_double,
        ) -> c_int;

        pub fn anubis_solve_argon2id(
            challenge_hex: *const c_char,
            difficulty: c_int,
            threads: c_int,
            budget_ms: c_double,
            out_nonce: *mut u32,
            out_hex: *mut c_char,
            out_ms: *mut c_double,
        ) -> c_int;

        pub fn anubis_solve_hashx(
            challenge_hex: *const c_char,
            difficulty: c_int,
            threads: c_int,
            budget_ms: c_double,
            out_nonce: *mut u32,
            out_hex: *mut c_char,
            out_ms: *mut c_double,
        ) -> c_int;

        pub fn anubis_verify_nibbles(
            challenge: *const c_char,
            nonce: u64,
            difficulty: c_int,
            out_hex: *mut c_char,
        ) -> c_int;
        pub fn anubis_verify_bits(
            challenge_hex: *const c_char,
            nonce: u32,
            difficulty: c_int,
            out_hex: *mut c_char,
        ) -> c_int;
        pub fn anubis_verify_argon2id(
            challenge_hex: *const c_char,
            nonce: u32,
            difficulty: c_int,
            out_hex: *mut c_char,
        ) -> c_int;
        pub fn anubis_verify_hashx(
            challenge_hex: *const c_char,
            nonce: u32,
            difficulty: c_int,
            out_hex: *mut c_char,
        ) -> c_int;
    }
}

/* -------------------------------------------------------------- helpers */

fn c_string(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::InteriorNul)
}

/// Read a NUL-terminated C string that the library owns, without assuming it
/// lives forever: `None` for a null pointer.
fn owned_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the library returns a valid NUL-terminated string for the
    // lifetime of the process; we copy it immediately.
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_owned)
}

fn hex_of(buf: &[c_char; 65]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let bytes: Vec<u8> = buf[..len].iter().map(|&c| c as u8).collect();
    String::from_utf8(bytes).unwrap_or_default()
}

/* -------------------------------------------------------- introspection */

/// The library version, e.g. `"1.2.1"`.
pub fn version() -> String {
    // SAFETY: no arguments, returns a static NUL-terminated string.
    owned_str(unsafe { ffi::anubis_solver_version() }).unwrap_or_default()
}

/// The active GPU backend, if one was configured.
pub fn gpu_info() -> Option<String> {
    // SAFETY: same contract as version().
    owned_str(unsafe { ffi::anubis_gpu_info() })
}

/// The library's idea of a sensible worker count.
pub fn default_threads() -> i32 {
    // SAFETY: no arguments, returns an int.
    unsafe { ffi::anubis_default_threads() }
}

/// Human-readable CPU affinity, if the platform has one.
pub fn cpu_affinity() -> Option<String> {
    // SAFETY: same contract as version().
    owned_str(unsafe { ffi::anubis_cpu_affinity_info() })
}

/// SHA-256 batch width: 16 (AVX-512), 8 (AVX2), 0 (scalar).
pub fn batch_width() -> i32 {
    // SAFETY: no arguments, returns an int.
    unsafe { ffi::anubis_batch_width() }
}

/// Enable or disable re-checking GPU hits on the CPU.
pub fn set_gpu_verify(enable: bool) {
    // SAFETY: an int argument, no pointer.
    unsafe { ffi::anubis_set_gpu_verify(if enable { 1 } else { 0 }) }
}

/// Whether GPU hits are re-checked on the CPU.
pub fn gpu_verify() -> bool {
    // SAFETY: no arguments, returns an int.
    unsafe { ffi::anubis_gpu_verify() != 0 }
}

/// Gather the introspection calls into one struct.
pub fn info() -> Info {
    Info {
        version: version(),
        gpu: gpu_info(),
        threads: default_threads(),
        affinity: cpu_affinity(),
        batch_width: batch_width(),
        gpu_verify: gpu_verify(),
    }
}

/* ---------------------------------------------------------------- sha256 */

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> Result<String, Error> {
    let mut out = [0 as c_char; 65];
    // SAFETY: `data` is valid for `data.len()` bytes, `out` is 65 bytes, which
    // is what the C function writes.
    let rc = unsafe {
        ffi::anubis_sha256_hex(data.as_ptr() as *const c_char, data.len(), out.as_mut_ptr())
    };
    if rc != OK {
        return Err(rc.into());
    }
    Ok(hex_of(&out))
}

/// SHA-256 midstate after `data`, whose length must be a multiple of 64.
pub fn sha256_midstate(data: &[u8]) -> Result<[u32; 8], Error> {
    if data.len() % 64 != 0 {
        return Err(Error::Argument);
    }
    let mut words = [0u32; 8];
    // SAFETY: length checked above; `words` holds the 8 words the C writes.
    let rc = unsafe {
        ffi::anubis_sha256_midstate(
            data.as_ptr() as *const c_char,
            data.len(),
            words.as_mut_ptr(),
        )
    };
    if rc != OK {
        return Err(rc.into());
    }
    Ok(words)
}

/* --------------------------------------------------------------- solving */

fn solve_with(
    f: unsafe extern "C" fn(*const c_char, c_int, c_int, c_double, *mut u32, *mut c_char, *mut c_double) -> c_int,
    challenge_hex: &str,
    difficulty: i32,
    opts: Options,
) -> Result<Solution, Error> {
    let c = c_string(challenge_hex)?;
    let mut nonce: u32 = 0;
    let mut hex = [0 as c_char; 65];
    let mut millis: c_double = 0.0;
    // SAFETY: the C string outlives the call, and every out-pointer refers to a
    // live local of the size the C function writes.
    let rc = unsafe {
        f(
            c.as_ptr(),
            difficulty,
            opts.threads,
            opts.budget_ms,
            &mut nonce,
            hex.as_mut_ptr(),
            &mut millis,
        )
    };
    if rc != OK {
        return Err(rc.into());
    }
    Ok(Solution { nonce: u64::from(nonce), hash: hex_of(&hex), millis })
}

/// Solve a `fast` or `slow` challenge: SHA-256 over `challenge || decimal nonce`,
/// with `difficulty` leading zero nibbles.
pub fn solve_nibbles(challenge: &str, difficulty: i32, opts: Options) -> Result<Solution, Error> {
    let c = c_string(challenge)?;
    let mut nonce: u64 = 0;
    let mut hex = [0 as c_char; 65];
    let mut millis: c_double = 0.0;
    // SAFETY: see solve_with.
    let rc = unsafe {
        ffi::anubis_solve_nibbles(
            c.as_ptr(),
            difficulty,
            opts.threads,
            opts.max_nonce,
            opts.budget_ms,
            &mut nonce,
            hex.as_mut_ptr(),
            &mut millis,
        )
    };
    if rc != OK {
        return Err(rc.into());
    }
    Ok(Solution { nonce, hash: hex_of(&hex), millis })
}

/// Solve a `sha256` (`wasm-sha256`) challenge: leading zero bits.
pub fn solve_sha256(challenge_hex: &str, difficulty: i32, opts: Options) -> Result<Solution, Error> {
    solve_with(ffi::anubis_solve_bits, challenge_hex, difficulty, opts)
}

/// Solve an `argon2id` challenge: leading zero bits.
pub fn solve_argon2id(challenge_hex: &str, difficulty: i32, opts: Options) -> Result<Solution, Error> {
    solve_with(ffi::anubis_solve_argon2id, challenge_hex, difficulty, opts)
}

/// Solve a `hashx` challenge: leading zero bits.
pub fn solve_hashx(challenge_hex: &str, difficulty: i32, opts: Options) -> Result<Solution, Error> {
    solve_with(ffi::anubis_solve_hashx, challenge_hex, difficulty, opts)
}

/// Solve with whichever algorithm the challenge names.
pub fn solve(
    algorithm: Algorithm,
    challenge: &str,
    difficulty: i32,
    opts: Options,
) -> Result<Solution, Error> {
    match algorithm {
        Algorithm::Fast | Algorithm::Slow => solve_nibbles(challenge, difficulty, opts),
        Algorithm::Sha256 => solve_sha256(challenge, difficulty, opts),
        Algorithm::Argon2id => solve_argon2id(challenge, difficulty, opts),
        Algorithm::Hashx => solve_hashx(challenge, difficulty, opts),
    }
}

/* ------------------------------------------------------------- verifying */

fn verify_with(
    f: unsafe extern "C" fn(*const c_char, u32, c_int, *mut c_char) -> c_int,
    challenge_hex: &str,
    nonce: u32,
    difficulty: i32,
) -> Result<(bool, String), Error> {
    let c = c_string(challenge_hex)?;
    let mut hex = [0 as c_char; 65];
    // SAFETY: the C string outlives the call; `hex` is the 65 bytes it writes.
    let rc = unsafe { f(c.as_ptr(), nonce, difficulty, hex.as_mut_ptr()) };
    match rc {
        OK => Ok((true, hex_of(&hex))),
        ERR_UNSOLVED => Ok((false, hex_of(&hex))),
        other => Err(other.into()),
    }
}

/// Re-check a `fast`/`slow` nonce. `false` means the nonce does not satisfy the
/// difficulty; the digest is returned either way.
pub fn verify_nibbles(challenge: &str, nonce: u64, difficulty: i32) -> Result<(bool, String), Error> {
    let c = c_string(challenge)?;
    let mut hex = [0 as c_char; 65];
    // SAFETY: see verify_with.
    let rc = unsafe { ffi::anubis_verify_nibbles(c.as_ptr(), nonce, difficulty, hex.as_mut_ptr()) };
    match rc {
        OK => Ok((true, hex_of(&hex))),
        ERR_UNSOLVED => Ok((false, hex_of(&hex))),
        other => Err(other.into()),
    }
}

/// Re-check a `sha256` (`wasm-sha256`) nonce.
pub fn verify_sha256(challenge_hex: &str, nonce: u32, difficulty: i32) -> Result<(bool, String), Error> {
    verify_with(ffi::anubis_verify_bits, challenge_hex, nonce, difficulty)
}

/// Re-check an `argon2id` nonce.
pub fn verify_argon2id(challenge_hex: &str, nonce: u32, difficulty: i32) -> Result<(bool, String), Error> {
    verify_with(ffi::anubis_verify_argon2id, challenge_hex, nonce, difficulty)
}

/// Re-check a `hashx` nonce.
pub fn verify_hashx(challenge_hex: &str, nonce: u32, difficulty: i32) -> Result<(bool, String), Error> {
    verify_with(ffi::anubis_verify_hashx, challenge_hex, nonce, difficulty)
}
