use protobuf_codegen::Codegen;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn get_protos(path: impl AsRef<Path>) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(path)
        .into_iter()
        .map(|res| res.expect("failed to read entry"))
        .filter(|entry| entry.path().is_file())
        .filter(|entry| {
            !entry
                .file_name()
                .to_str()
                .expect("invalid filename")
                .starts_with('.')
        })
        .map(|entry| entry.into_path())
}

fn main() {
    print_rerun_if_changed_recursively("protos");

    Codegen::new()
        .pure()
        .cargo_out_dir("generated")
        .include("protos")
        .inputs(get_protos("protos"))
        .run_from_script();
}

fn print_rerun_if_changed<P: AsRef<Path>>(path: P) {
    println!("cargo:rerun-if-changed={}", path.as_ref().display());
}

pub fn print_rerun_if_changed_recursively<P: AsRef<Path>>(path: P) {
    get_protos(path).for_each(print_rerun_if_changed)
}
