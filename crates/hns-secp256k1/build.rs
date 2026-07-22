use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = manifest.join("../../vendor/secp256k1");
    let source = root.join("src/secp256k1.c");

    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("include/secp256k1.h").display()
    );
    println!("cargo:rerun-if-changed={}", root.join("COPYING").display());

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .file(source)
        .include(&root)
        .include(root.join("include"))
        .include(root.join("src"))
        .define("USE_NUM_NONE", "1")
        .define("USE_FIELD_INV_BUILTIN", "1")
        .define("USE_SCALAR_INV_BUILTIN", "1")
        .define("ECMULT_WINDOW_SIZE", "15")
        .define("ECMULT_GEN_PREC_BITS", "4")
        .define("USE_ENDOMORPHISM", "1")
        // HSD's Brontide transport uses the pinned implementation's raw ECDH
        // point and Elligator-Squared public-key encoding. Keep those modules
        // in the same static library as consensus verification so there is a
        // single audited secp256k1 revision in the workspace.
        .define("ENABLE_MODULE_ECDH", "1")
        .define("ENABLE_MODULE_ELLIGATOR", "1")
        .warnings(false);

    // This pinned libsecp256k1 revision selects its field/scalar layout through
    // these definitions. GCC/Clang support unsigned __int128 on ordinary 64-bit
    // targets; MSVC and 32-bit targets use the portable 64-bit path.
    if pointer_width == "64" && target_env != "msvc" {
        build.define("USE_FORCE_WIDEMUL_INT128", "1");
    } else {
        build.define("USE_FORCE_WIDEMUL_INT64", "1");
    }

    build
        .flag_if_supported("-std=c89")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-Wno-unused-function")
        .compile("hsrd_secp256k1");
}
