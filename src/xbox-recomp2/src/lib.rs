//! Recompiles guest x86 functions into C++ source files.
//!
//! # Entry points
//!
//! - [`run_with`]: all steps in one call.
//! - [`Recompiler::load_input`], [`Recompiler::analyse`] and
//!   [`Recompiler::recompile`]: one step at a time.
//! - [`Recompiler::generate_in_memory`]: builds files without writing them.
//!
//! # Layout
//!
//! - [`Recompiler`]: drives the steps.
//! - `codegen/function/`: turns functions into C++.
//! - `output/`: writes the files.

pub use crate::context_header::assemble_context_header;
pub use crate::recompiler::{LoadError, Recompiler, RunError, WrongAnalyse};
pub use codegen::templates;
pub use output::GeneratedFileSet;
pub(crate) use output::MemoryWriter;
pub use output::{DiskWriter, OutError};
use std::io::Write;
use std::path::Path;
pub use xbox_recomp2_recomp_config as config;

pub mod analysis;
mod codegen;
mod context_header;
pub mod decode;
pub mod executable;
mod output;
pub mod platform;
mod recompiler;
pub mod stats;
mod utils;

/// Runs the full recompiler on `input`.
///
/// See `doc/docs/how-it-works.md` for an overview.
///
/// # Arguments
///
/// * `input` - config TOML.
/// * `formats` - executable formats used to parse the configured binary.
/// * `platform` - the target platform, like Xbox.
/// * `diag` - receives progress and diagnostics.
///
/// # Errors
///
/// Diagnostics for each error are already in `diag`.
///
/// - [`RunError::Load`]: `input` can't be read, the config is malformed, or
///   its binary is missing or empty. See [`LoadError`].
/// - [`RunError::NoDerivableFunctions`]: discovery found no functions.
///   List them under `fixes.functions` in a config.
/// - [`RunError::MissingEntryPoint`]: no function at the entry point.
///   Check exclusion ranges or add its range to `fixes.functions`.
/// - [`RunError::DuplicateName`]: another symbol or alias already has this name.
///   Pick a different alias.
/// - [`RunError::Out`]: writing the output failed.
pub fn run_with(
    input: &Path,
    formats: &[&dyn executable::ExecutableFormat],
    platform: &dyn platform::GuestPlatform,
    diag: &mut dyn Write,
    hash_funcs: Option<&[String]>
) -> Result<(), RunError> {
    let mut recompiler = Recompiler::load_input(input, formats, platform, diag)?;
    recompiler.analyse_requiring_functions(input, diag)?;
    recompiler.recompile(diag).map_err(RunError::Out)?;

    if let Some(names) = hash_funcs {
        recompiler.print_function_hashes(names, diag);
    }
    Ok(())
}
