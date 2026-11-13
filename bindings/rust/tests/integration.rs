//! Runs the bindings against the real library.
//!
//!     cd bindings/rust && cargo test
use anubis_solver as anubis;

const HEX: &str = "00112233445566778899aabbccddeeff";

fn looks_like_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[test]
fn info_is_populated() {
    let i = anubis::info();
    let parts: Vec<&str> = i.version.split('.').collect();
    assert_eq!(parts.len(), 3, "version {:?}", i.version);
    assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()));
    assert!(i.threads >= 1);
    println!(
        "version {} | gpu {:?} | threads {} | affinity {:?} | batch {}",
        i.version, i.gpu, i.threads, i.affinity, i.batch_width
    );
}

#[test]
fn sha256_hex_matches_a_known_digest() {
    assert_eq!(
        anubis::sha256_hex(b"abc").unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        anubis::sha256_hex(b"").unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn midstate_needs_a_multiple_of_64() {
    let block = [b'a'; 64];
    assert_eq!(anubis::sha256_midstate(&block).unwrap().len(), 8);
    assert_eq!(anubis::sha256_midstate(&block[..63]), Err(anubis::Error::Argument));
}

#[test]
fn nibbles_solve_and_verify() {
    let r = anubis::solve_nibbles("demo-challenge", 3, anubis::Options::default()).unwrap();
    assert!(looks_like_digest(&r.hash), "hash {:?}", r.hash);
    assert!(r.millis >= 0.0);

    let (ok, hash) = anubis::verify_nibbles("demo-challenge", r.nonce, 3).unwrap();
    assert!(ok, "nonce {} did not verify", r.nonce);
    assert_eq!(hash, r.hash);

    let (ok, _) = anubis::verify_nibbles("demo-challenge", 999_999, 3).unwrap();
    assert!(!ok, "a wrong nonce verified");
}

#[test]
fn every_bits_family_solves_and_verifies() {
    for (algo, difficulty) in [
        (anubis::Algorithm::Sha256, 8),
        (anubis::Algorithm::Argon2id, 4),
        (anubis::Algorithm::Hashx, 4),
    ] {
        let r = anubis::solve(algo, HEX, difficulty, anubis::Options::default())
            .unwrap_or_else(|e| panic!("{algo:?}: {e}"));
        assert!(looks_like_digest(&r.hash), "{algo:?} hash {:?}", r.hash);

        let (ok, hash) = match algo {
            anubis::Algorithm::Sha256 => anubis::verify_sha256(HEX, r.nonce as u32, difficulty),
            anubis::Algorithm::Argon2id => anubis::verify_argon2id(HEX, r.nonce as u32, difficulty),
            _ => anubis::verify_hashx(HEX, r.nonce as u32, difficulty),
        }
        .unwrap();
        assert!(ok, "{algo:?}: nonce {} did not verify", r.nonce);
        assert_eq!(hash, r.hash, "{algo:?}: verify digest differs");
    }
}

#[test]
fn algorithm_parse_covers_the_names_anubis_uses() {
    assert_eq!(anubis::Algorithm::parse("fast"), Some(anubis::Algorithm::Fast));
    assert_eq!(anubis::Algorithm::parse("wasm-sha256"), Some(anubis::Algorithm::Sha256));
    assert_eq!(anubis::Algorithm::parse("metarefresh"), None);
}

#[test]
fn an_exhausted_budget_is_an_error_value() {
    let opts = anubis::Options { budget_ms: 1.0, ..Default::default() };
    assert_eq!(
        anubis::solve_nibbles("demo-challenge", 64, opts),
        Err(anubis::Error::Unsolved)
    );
}

#[test]
fn malformed_hex_is_an_argument_error() {
    assert_eq!(
        anubis::solve_sha256("not-hex", 4, anubis::Options::default()),
        Err(anubis::Error::Argument)
    );
}

#[test]
fn an_independent_digest_matches_the_solver() {
    let r = anubis::solve_sha256(HEX, 4, anubis::Options::default()).unwrap();

    let raw: Vec<u8> = (0..HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&HEX[i..i + 2], 16).unwrap())
        .collect();
    // the core picks the nonce byte order from the challenge's last byte
    let nonce = r.nonce as u32;
    let nb = if raw[raw.len() - 1] >= 0x80 {
        nonce.to_le_bytes()
    } else {
        nonce.to_be_bytes()
    };
    let mut buf = raw.clone();
    buf.extend_from_slice(&nb);
    assert_eq!(anubis::sha256_hex(&buf).unwrap(), r.hash);
}
