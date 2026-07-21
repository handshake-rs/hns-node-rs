use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = manifest.join("../../vendor/goosig");
    let source_root = root.join("src/goo");
    let sources = ["drbg.c", "goo.c", "hmac.c", "mini-gmp.c", "sha256.c"];
    let headers = [
        "drbg.h",
        "goo.h",
        "hmac.h",
        "internal.h",
        "mini-gmp.h",
        "primes.h",
        "sha256.h",
        "util.h",
    ];

    for source in sources {
        println!(
            "cargo:rerun-if-changed={}",
            source_root.join(source).display()
        );
    }
    for header in headers {
        println!(
            "cargo:rerun-if-changed={}",
            source_root.join(header).display()
        );
    }
    println!("cargo:rerun-if-changed={}", root.join("LICENSE").display());

    let mut build = cc::Build::new();
    build
        .files(sources.map(|source| source_root.join(source)))
        .include(&source_root)
        .warnings(false)
        .flag_if_supported("-std=c89")
        .flag_if_supported("-fvisibility=hidden");

    if env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("big") {
        build.define("WORDS_BIGENDIAN", "1");
    }

    build.compile("hsrd_goosig");
}
