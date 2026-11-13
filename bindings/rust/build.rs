//! Points the linker at the repository root and bakes in an rpath, so a binary
//! built here finds libanubis_solver.so without LD_LIBRARY_PATH.
//!
//! Override with ANUBIS_LIB_DIR (the directory holding the .so/.dylib):
//!   ANUBIS_LIB_DIR=/opt/anubis cargo build

use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo = manifest
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest.clone());

    let lib_dir = std::env::var("ANUBIS_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or(repo);

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=anubis_solver");

    // rpath so `cargo run` and `cargo test` work from anywhere
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../../..");
    } else {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }

    println!("cargo:rerun-if-env-changed=ANUBIS_LIB_DIR");
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:warning=anubis-solver: linking against {} (build it with `make` at the repo root)",
        lib_dir.display()
    );
}
