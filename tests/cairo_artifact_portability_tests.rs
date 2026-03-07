use std::path::PathBuf;

use tempfile::tempdir;
use zk_fuzzer::targets::CairoTarget;

fn repo_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn cairo0_compilation_does_not_embed_absolute_source_paths() {
    if CairoTarget::check_cairo_available().is_err() {
        eprintln!(
            "skipping cairo0_compilation_does_not_embed_absolute_source_paths (cairo-compile unavailable)"
        );
        return;
    }

    let source_path = repo_path()
        .join("tests")
        .join("cairo_programs")
        .join("multiplier.cairo");
    let build_dir = tempdir().expect("temp build dir");

    let mut target = CairoTarget::new(source_path.to_str().expect("utf8 source path"))
        .expect("create cairo target")
        .with_build_dir(build_dir.path().to_path_buf());
    target.compile().expect("compile cairo source");

    let artifact_path = build_dir.path().join("multiplier.json");
    let artifact = std::fs::read_to_string(&artifact_path).expect("read compiled cairo artifact");
    let absolute_source = source_path
        .to_str()
        .expect("utf8 absolute source path")
        .to_string();

    assert!(
        !artifact.contains(&absolute_source),
        "compiled Cairo artifact embedded absolute source path: {}",
        absolute_source
    );
}
