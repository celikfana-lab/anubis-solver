// Go demo: solve an Anubis challenge through libanubis_solver.
//
//	go run ./examples/go_demo        (from the repository root, after `make`)
package main

import (
	"fmt"
	"log"

	anubis "github.com/celikfana-lab/anubis-solver/bindings/go"
)

func main() {
	info := anubis.GetInfo()
	fmt.Printf("libanubis_solver %s  gpu %s  threads %d  batch %d\n",
		info.Version, orNone(info.GPU), info.Threads, info.BatchWidth)

	// fast / slow: SHA-256 over challenge || decimal nonce, leading zero nibbles
	nib, err := anubis.SolveNibbles("demo-challenge", 3, anubis.Opts{})
	if err != nil {
		log.Fatalf("solve: %v", err)
	}
	fmt.Printf("nibbles   nonce %d  %s  %.3f ms\n", nib.Nonce, nib.Hash, nib.Millis)

	ok, hash, err := anubis.VerifyNibbles("demo-challenge", nib.Nonce, 3)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("verify    %s  %s\n", okStr(ok), sameStr(hash, nib.Hash))

	// sha256 / argon2id / hashx: leading zero bits, hex challenge
	const hex = "00112233445566778899aabbccddeeff"
	bits, err := anubis.Solve("sha256", hex, 8, anubis.Opts{})
	if err != nil {
		log.Fatalf("solve sha256: %v", err)
	}
	fmt.Printf("sha256    nonce %d  %s\n", bits.Nonce, bits.Hash)
	ok, _, err = anubis.VerifySHA256(hex, uint32(bits.Nonce), 8)
	if err != nil {
		log.Fatalf("verify sha256: %v", err)
	}
	fmt.Printf("verify    %s\n", okStr(ok))

	// the library's own SHA-256, to cross-check a digest independently
	sum, err := anubis.SHA256Hex([]byte("abc"))
	if err != nil {
		log.Fatalf("sha256: %v", err)
	}
	fmt.Printf("sha256(\"abc\") = %s\n", sum)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func okStr(ok bool) string {
	if ok {
		return "ok"
	}
	return "FAILED"
}

func sameStr(a, b string) string {
	if a == b {
		return "same digest"
	}
	return "DIFFERENT digest"
}
