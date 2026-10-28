use std::path::PathBuf;

fn main() {
    let manifest =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let source = std::fs::read_to_string(manifest).expect("read frontend manifest");
    let parsed: toml::Value = toml::from_str(&source).expect("parse frontend manifest");
    for (name, output) in [
        ("hermit", "HERMIT_PATCHING_CORE_H_REV"),
        ("reverie", "HERMIT_PATCHING_CORE_R_REV"),
    ] {
        let revision = parsed["dependencies"][name]["rev"]
            .as_str()
            .expect("static frontend dependencies require an exact core revision");
        assert!(revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
        println!("cargo:rustc-env={output}={revision}");
    }
}
