use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use std::env;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;

const SYSTEM_PUBLIC_KEY_BYTES: &str = include_str!("system.pem");

fn main() {
    println!("cargo:rerun-if-changed=system.pem");
    println!("cargo:rerun-if-changed=build.rs");
    let key =
        RsaPublicKey::from_public_key_pem(SYSTEM_PUBLIC_KEY_BYTES).expect("invalid public key");
    let e = key.e().to_bytes_le();
    let n = key.n().to_bytes_le();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("system_key.rs");

    let source = format!(
        r##"
        pub const E: &[u8] = &[{}];
        pub const N: &[u8] = &[{}];
    "##,
        CommaSeperated(e),
        CommaSeperated(n),
    );
    fs::write(dest_path, source).expect("Failed to write system_key.rs");
}

struct CommaSeperated<T>(Vec<T>);

impl<T> Display for CommaSeperated<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut items = self.0.iter();
        if let Some(first) = items.next() {
            write!(f, "{first}")?;
        }
        for item in items {
            write!(f, ", {item}")?;
        }
        Ok(())
    }
}
