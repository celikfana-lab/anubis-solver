// Package anubis solves Anubis proof-of-work challenges through
// libanubis_solver.so (cgo, no build tags, no extra dependencies).
//
// Build the shared library first, from the repository root:
//
//	make
//
// then, from bindings/go:
//
//	go test ./...
//
// The rpath is baked in as ${SRCDIR}/../.., so a program compiled against this
// package finds the library next to the repository without LD_LIBRARY_PATH. To
// point somewhere else: CGO_LDFLAGS="-L/path/to/lib" go build.
package anubis

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../.. -Wl,-rpath,${SRCDIR}/../.. -lanubis_solver
#include <stdlib.h>
#include "anubis-solver.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Return codes from anubis-solver.h.
const (
	OK         = 0
	ErrArgC    = 1
	ErrUnsolvC = 2
	ErrInternC = 3
)

var (
	// ErrArg is a bad argument: a malformed hex challenge, a difficulty out of
	// range, or a nil output pointer.
	ErrArg = errors.New("anubis: invalid argument")
	// ErrUnsolved means the nonce or time budget was exhausted.
	ErrUnsolved = errors.New("anubis: exhausted the nonce or time budget")
	// ErrInternal is a backend or library failure.
	ErrInternal = errors.New("anubis: internal error")
)

func codeToError(rc C.int) error {
	switch int(rc) {
	case OK:
		return nil
	case ErrArgC:
		return ErrArg
	case ErrUnsolvC:
		return ErrUnsolved
	case ErrInternC:
		return ErrInternal
	default:
		return fmt.Errorf("anubis: unknown return code %d", int(rc))
	}
}

// ---------------------------------------------------------------- introspect

// Version is the library version, e.g. "1.1.0".
func Version() string { return C.GoString(C.anubis_solver_version()) }

// GPUInfo names the active GPU backend, or "" when there is none.
func GPUInfo() string {
	p := C.anubis_gpu_info()
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// DefaultThreads is the library's idea of a sensible worker count.
func DefaultThreads() int { return int(C.anubis_default_threads()) }

// CPUAffinity describes the CPU affinity the library picked.
func CPUAffinity() string {
	p := C.anubis_cpu_affinity_info()
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// BatchWidth is the SHA-256 batch width: 16 (AVX-512), 8 (AVX2), 0 (scalar).
func BatchWidth() int { return int(C.anubis_batch_width()) }

// SetGPUVerify enables or disables re-checking GPU hits on the CPU.
func SetGPUVerify(enable bool) {
	v := C.int(0)
	if enable {
		v = 1
	}
	C.anubis_set_gpu_verify(v)
}

// GPUVerify reports whether GPU hits are re-checked.
func GPUVerify() bool { return C.anubis_gpu_verify() != 0 }

// Info gathers the introspection calls into one struct.
type Info struct {
	Version     string
	GPU         string
	Threads     int
	Affinity    string
	BatchWidth  int
	GPUVerifies bool
}

// GetInfo fills an Info from the library.
func GetInfo() Info {
	return Info{
		Version:     Version(),
		GPU:         GPUInfo(),
		Threads:     DefaultThreads(),
		Affinity:    CPUAffinity(),
		BatchWidth:  BatchWidth(),
		GPUVerifies: GPUVerify(),
	}
}

// -------------------------------------------------------------- sha256 utils

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) (string, error) {
	var out [65]C.char
	var p unsafe.Pointer
	if len(data) > 0 {
		p = unsafe.Pointer(&data[0])
	}
	rc := C.anubis_sha256_hex((*C.char)(p), C.size_t(len(data)), &out[0])
	if err := codeToError(rc); err != nil {
		return "", err
	}
	return C.GoString(&out[0]), nil
}

// SHA256Midstate returns the midstate after data, whose length must be a
// multiple of 64 bytes.
func SHA256Midstate(data []byte) ([8]uint32, error) {
	var out [8]C.uint32_t
	if len(data)%64 != 0 {
		return [8]uint32{}, ErrArg
	}
	var p unsafe.Pointer
	if len(data) > 0 {
		p = unsafe.Pointer(&data[0])
	}
	rc := C.anubis_sha256_midstate((*C.char)(p), C.size_t(len(data)), &out[0])
	if err := codeToError(rc); err != nil {
		return [8]uint32{}, err
	}
	var ret [8]uint32
	for i := range ret {
		ret[i] = uint32(out[i])
	}
	return ret, nil
}

// ------------------------------------------------------------------- solving

// Opts are the optional knobs. The zero value is "pick threads yourself, no
// nonce limit, no time limit".
type Opts struct {
	// Threads is 0 for the library default.
	Threads int
	// MaxNonce bounds the search; 0 or negative means no limit.
	MaxNonce int64
	// BudgetMS bounds the search in milliseconds; 0 or negative means none.
	BudgetMS float64
}

// Result is a solved challenge.
type Result struct {
	Nonce  uint64
	Hash   string
	Millis float64
}

func challengeCString(c string) (*C.char, func()) {
	cs := C.CString(c)
	return cs, func() { C.free(unsafe.Pointer(cs)) }
}

// SolveNibbles solves a `fast` or `slow` challenge: SHA-256 over
// challenge||decimal nonce, with `difficulty` leading zero nibbles.
func SolveNibbles(challenge string, difficulty int, o Opts) (Result, error) {
	cs, free := challengeCString(challenge)
	defer free()

	var nonce C.uint64_t
	var hex [65]C.char
	var ms C.double
	maxNonce := o.MaxNonce
	if maxNonce == 0 {
		maxNonce = -1 // no limit, as the reference bindings do
	}
	rc := C.anubis_solve_nibbles(cs, C.int(difficulty), C.int(o.Threads),
		C.int64_t(maxNonce), C.double(o.BudgetMS), &nonce, &hex[0], &ms)
	if err := codeToError(rc); err != nil {
		return Result{}, err
	}
	return Result{Nonce: uint64(nonce), Hash: C.GoString(&hex[0]), Millis: float64(ms)}, nil
}

func solveBits(kind string, challengeHex string, difficulty int, o Opts) (Result, error) {
	cs, free := challengeCString(challengeHex)
	defer free()

	var nonce C.uint32_t
	var hex [65]C.char
	var ms C.double
	var rc C.int
	switch kind {
	case "sha256":
		rc = C.anubis_solve_bits(cs, C.int(difficulty), C.int(o.Threads),
			C.double(o.BudgetMS), &nonce, &hex[0], &ms)
	case "argon2id":
		rc = C.anubis_solve_argon2id(cs, C.int(difficulty), C.int(o.Threads),
			C.double(o.BudgetMS), &nonce, &hex[0], &ms)
	case "hashx":
		rc = C.anubis_solve_hashx(cs, C.int(difficulty), C.int(o.Threads),
			C.double(o.BudgetMS), &nonce, &hex[0], &ms)
	default:
		return Result{}, ErrArg
	}
	if err := codeToError(rc); err != nil {
		return Result{}, err
	}
	return Result{Nonce: uint64(nonce), Hash: C.GoString(&hex[0]), Millis: float64(ms)}, nil
}

// SolveSHA256 solves a `sha256` (wasm) challenge: SHA-256 over the raw
// challenge bytes || uint32 nonce, with `difficulty` leading zero bits.
// challengeHex is the hex-encoded challenge.
func SolveSHA256(challengeHex string, difficulty int, o Opts) (Result, error) {
	return solveBits("sha256", challengeHex, difficulty, o)
}

// SolveArgon2id solves an `argon2id` challenge, difficulty in leading zero bits.
func SolveArgon2id(challengeHex string, difficulty int, o Opts) (Result, error) {
	return solveBits("argon2id", challengeHex, difficulty, o)
}

// SolveHashx solves a `hashx` challenge, difficulty in leading zero bits.
func SolveHashx(challengeHex string, difficulty int, o Opts) (Result, error) {
	return solveBits("hashx", challengeHex, difficulty, o)
}

// Solve dispatches on the algorithm name Anubis uses: fast, slow, sha256,
// wasm-sha256, argon2id or hashx.
func Solve(algorithm, challenge string, difficulty int, o Opts) (Result, error) {
	switch algorithm {
	case "fast", "slow":
		return SolveNibbles(challenge, difficulty, o)
	case "sha256", "wasm-sha256":
		return SolveSHA256(challenge, difficulty, o)
	case "argon2id":
		return SolveArgon2id(challenge, difficulty, o)
	case "hashx":
		return SolveHashx(challenge, difficulty, o)
	default:
		return Result{}, fmt.Errorf("anubis: unknown algorithm %q", algorithm)
	}
}

// ----------------------------------------------------------------- verifying

// VerifyNibbles re-checks a `fast`/`slow` nonce. ok is false when the nonce
// does not satisfy the difficulty; the hash is returned either way.
func VerifyNibbles(challenge string, nonce uint64, difficulty int) (ok bool, hash string, err error) {
	cs, free := challengeCString(challenge)
	defer free()
	var hex [65]C.char
	rc := C.anubis_verify_nibbles(cs, C.uint64_t(nonce), C.int(difficulty), &hex[0])
	if rc != C.int(OK) && rc != C.int(ErrUnsolvC) {
		return false, "", codeToError(rc)
	}
	return rc == C.int(OK), C.GoString(&hex[0]), nil
}

func verifyBits(kind, challengeHex string, nonce uint32, difficulty int) (bool, string, error) {
	cs, free := challengeCString(challengeHex)
	defer free()
	var hex [65]C.char
	var rc C.int
	switch kind {
	case "sha256":
		rc = C.anubis_verify_bits(cs, C.uint32_t(nonce), C.int(difficulty), &hex[0])
	case "argon2id":
		rc = C.anubis_verify_argon2id(cs, C.uint32_t(nonce), C.int(difficulty), &hex[0])
	case "hashx":
		rc = C.anubis_verify_hashx(cs, C.uint32_t(nonce), C.int(difficulty), &hex[0])
	default:
		return false, "", ErrArg
	}
	if rc != C.int(OK) && rc != C.int(ErrUnsolvC) {
		return false, "", codeToError(rc)
	}
	return rc == C.int(OK), C.GoString(&hex[0]), nil
}

// VerifySHA256 re-checks a `sha256` (wasm) nonce.
func VerifySHA256(challengeHex string, nonce uint32, difficulty int) (bool, string, error) {
	return verifyBits("sha256", challengeHex, nonce, difficulty)
}

// VerifyArgon2id re-checks an `argon2id` nonce.
func VerifyArgon2id(challengeHex string, nonce uint32, difficulty int) (bool, string, error) {
	return verifyBits("argon2id", challengeHex, nonce, difficulty)
}

// VerifyHashx re-checks a `hashx` nonce.
func VerifyHashx(challengeHex string, nonce uint32, difficulty int) (bool, string, error) {
	return verifyBits("hashx", challengeHex, nonce, difficulty)
}
