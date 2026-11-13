//! Solve an Anubis challenge from Rust.
//!
//!     cd bindings/rust
//!     cargo run --example solve
//!
//! Build the library first, from the repository root: `make`.
use anubis_solver as anubis;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let i = anubis::info();
    println!(
        "libanubis_solver {}  gpu {}  threads {}  batch {}",
        i.version,
        i.gpu.as_deref().unwrap_or("(none)"),
        i.threads,
        i.batch_width
    );

    // fast / slow: SHA-256 over challenge || decimal nonce, leading zero nibbles
    let nib = anubis::solve_nibbles("demo-challenge", 3, anubis::Options::default())?;
    println!("nibbles   nonce {}  {}  {:.3} ms", nib.nonce, nib.hash, nib.millis);
    let (ok, hash) = anubis::verify_nibbles("demo-challenge", nib.nonce, 3)?;
    println!(
        "verify    {}  {}",
        if ok { "ok" } else { "FAILED" },
        if hash == nib.hash { "same digest" } else { "DIFFERENT digest" }
    );

    // sha256 / argon2id / hashx: leading zero bits, hex challenge
    const HEX: &str = "00112233445566778899aabbccddeeff";
    let bits = anubis::solve(anubis::Algorithm::Sha256, HEX, 8, anubis::Options::default())?;
    println!("sha256    nonce {}  {}", bits.nonce, bits.hash);
    let (ok, _) = anubis::verify_sha256(HEX, bits.nonce as u32, 8)?;
    println!("verify    {}", if ok { "ok" } else { "FAILED" });

    // the library's own SHA-256, to cross-check a digest independently
    println!("sha256(\"abc\") = {}", anubis::sha256_hex(b"abc")?);

    // an exhausted budget is an error value, not a panic
    match anubis::solve_nibbles(
        "demo-challenge",
        64,
        anubis::Options { budget_ms: 1.0, ..Default::default() },
    ) {
        Err(anubis::Error::Unsolved) => println!("unsolvable budget -> Error::Unsolved"),
        Err(e) => println!("unexpected error: {e}"),
        Ok(r) => println!("unexpectedly solved: nonce {}", r.nonce),
    }

    Ok(())
}
