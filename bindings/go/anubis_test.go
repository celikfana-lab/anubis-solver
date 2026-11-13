package anubis

import (
	"encoding/hex"
	"errors"
	"regexp"
	"testing"
)

const hexChallenge = "00112233445566778899aabbccddeeff"

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestInfo(t *testing.T) {
	i := GetInfo()
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(i.Version) {
		t.Fatalf("version %q does not look like a version", i.Version)
	}
	if i.Threads < 1 {
		t.Fatalf("default threads = %d", i.Threads)
	}
	t.Logf("version %s | gpu %q | threads %d | affinity %q | batch %d",
		i.Version, i.GPU, i.Threads, i.Affinity, i.BatchWidth)
}

func TestSHA256Hex(t *testing.T) {
	got, err := SHA256Hex([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	// echo -n abc | sha256sum
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("sha256(abc) = %s, want %s", got, want)
	}
}

func TestSHA256HexEmpty(t *testing.T) {
	got, err := SHA256Hex(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("empty digest %q", got)
	}
}

func TestSHA256Midstate(t *testing.T) {
	block := make([]byte, 64)
	for i := range block {
		block[i] = 'a'
	}
	st, err := SHA256Midstate(block)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SHA256Midstate(block[:63]); !errors.Is(err, ErrArg) {
		t.Fatalf("a 63-byte midstate should be ErrArg, got %v", err)
	}
	t.Logf("midstate[0..1] = %08x %08x", st[0], st[1])
}

func TestNibbles(t *testing.T) {
	r, err := SolveNibbles("demo-challenge", 3, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if !hexDigest.MatchString(r.Hash) {
		t.Fatalf("hash %q", r.Hash)
	}
	ok, hash, err := VerifyNibbles("demo-challenge", r.Nonce, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("nonce %d does not verify", r.Nonce)
	}
	if hash != r.Hash {
		t.Fatalf("verify hash %s != solve hash %s", hash, r.Hash)
	}
	if ok, _, err := VerifyNibbles("demo-challenge", r.Nonce+1_000_003, 3); err != nil || ok {
		t.Fatalf("a wrong nonce verified (ok=%v err=%v)", ok, err)
	}
}

func TestBitsFamilies(t *testing.T) {
	cases := []struct {
		name   string
		solve  func(string, int, Opts) (Result, error)
		verify func(string, uint32, int) (bool, string, error)
		dif    int
	}{
		{"sha256", SolveSHA256, VerifySHA256, 8},
		{"argon2id", SolveArgon2id, VerifyArgon2id, 4},
		{"hashx", SolveHashx, VerifyHashx, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := c.solve(hexChallenge, c.dif, Opts{})
			if err != nil {
				t.Fatal(err)
			}
			if !hexDigest.MatchString(r.Hash) {
				t.Fatalf("hash %q", r.Hash)
			}
			ok, hash, err := c.verify(hexChallenge, uint32(r.Nonce), c.dif)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || hash != r.Hash {
				t.Fatalf("verify ok=%v hash=%s want %s", ok, hash, r.Hash)
			}
		})
	}
}

func TestSolveDispatch(t *testing.T) {
	for _, algo := range []string{"fast", "sha256", "argon2id", "hashx"} {
		challenge := "demo-challenge"
		dif := 2
		if algo != "fast" {
			challenge, dif = hexChallenge, 4
		}
		r, err := Solve(algo, challenge, dif, Opts{})
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if r.Nonce > 1<<32 {
			t.Fatalf("%s: nonce %d", algo, r.Nonce)
		}
	}
	if _, err := Solve("md5", "x", 1, Opts{}); err == nil {
		t.Fatal("an unknown algorithm should be an error")
	}
}

func TestUnsolvedIsACode(t *testing.T) {
	_, err := SolveNibbles("demo-challenge", 64, Opts{BudgetMS: 1})
	if !errors.Is(err, ErrUnsolved) {
		t.Fatalf("expected ErrUnsolved, got %v", err)
	}
}

func TestMalformedHexIsErrArg(t *testing.T) {
	_, err := SolveSHA256("not-hex", 4, Opts{})
	if !errors.Is(err, ErrArg) {
		t.Fatalf("expected ErrArg, got %v", err)
	}
}

func TestDigestMatchesSolver(t *testing.T) {
	// The sha256 family hashes raw challenge||nonce. The core picks the nonce
	// byte order from the challenge's last byte: little-endian when it is
	// >= 0x80, big-endian otherwise (see the use_le assignment in
	// src/core/anubis_solver.c). Mirror that rule here instead of assuming one.
	r, err := SolveSHA256(hexChallenge, 4, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(hexChallenge)
	if err != nil {
		t.Fatal(err)
	}
	le := len(raw) > 0 && raw[len(raw)-1] >= 0x80
	var nb [4]byte
	if le {
		nb = [4]byte{byte(r.Nonce), byte(r.Nonce >> 8), byte(r.Nonce >> 16), byte(r.Nonce >> 24)}
	} else {
		nb = [4]byte{byte(r.Nonce >> 24), byte(r.Nonce >> 16), byte(r.Nonce >> 8), byte(r.Nonce)}
	}
	sum, err := SHA256Hex(append(append([]byte{}, raw...), nb[:]...))
	if err != nil {
		t.Fatal(err)
	}
	if sum != r.Hash {
		t.Fatalf("independent digest %s != solver digest %s (little-endian nonce: %v)",
			sum, r.Hash, le)
	}
	t.Logf("nonce %d (%s bytes) reproduces %s", r.Nonce, map[bool]string{true: "le", false: "be"}[le], sum)
}
