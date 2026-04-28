use vergen_gitcl::{Emitter, RustcBuilder};

fn main() -> anyhow::Result<()> {
    let rustc = RustcBuilder::default().semver(true).build()?;

    Emitter::default().add_instructions(&rustc)?.emit()?;

    Ok(())
}
