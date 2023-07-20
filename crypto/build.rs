use std::env;
use std::fs;
use std::path::Path;

const SYSTEM_PUBLIC_KEY_BYTES: &str = include_str!("system.pem");

fn main() {
    println!("cargo:rerun-if-changed=system.pem");
    println!("cargo:rerun-if-changed=build.rs");
    let der_encoded = SYSTEM_PUBLIC_KEY_BYTES
        .split('\n')
        .filter(|line| !line.starts_with('-'))
        .fold(String::new(), |mut data, line| {
            data.push_str(line);
            data
        });
    let der_bytes = base64::decode(der_encoded).expect("failed to decode base64 content");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("system.der");

    fs::write(dest_path, der_bytes).expect("Failed to write system.der");
}
