use vergen_gitcl::{Emitter, Rustc};

fn main() -> anyhow::Result<()> {
    let rustc = Rustc::builder().semver(true).build();

    Emitter::default().add_instructions(&rustc)?.emit()?;

    Ok(())
}
