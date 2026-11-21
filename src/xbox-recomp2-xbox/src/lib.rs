//! Xbox executable support for the XboxRecomp2 recompiler.
//!
//! # Crate map
//!
//! ```text
//! lib.rs        crate root: the built-in format list, XbeFormat, parse_executable etc.
//! xbe/          parse XBE into the format-neutral Executable
//!   header.rs   XBE header structs
//!   kernel/     kernel thunk (import) table support
//! platform/     the Xbox GuestPlatform
//! context.rs    the x86_context.h overlay (x86_context_xbox.h)
//! ```
//!
//! Call [`run`] to execute the XboxRecomp2 recompiler pipeline with
//! Xbox defaults; use [`parse_executable`] to parse XBE bytes
//! alone.

pub use context::context_header;
pub use platform::{XBOX, Xbox};
use std::io::Write;
use std::path::Path;
use xbox_recomp2::RunError;
use xbox_recomp2_executable::{Executable, ExecutableFormat, parse_executable_with};

mod context;
mod platform;
pub mod xbe;

/// The formats [`parse_executable`] and [`run`] probe, in order.
pub(crate) const BUILTIN_FORMATS: [&dyn ExecutableFormat; 1] = [&XbeFormat];

/// The Xbox executable (XBE) format.
pub struct XbeFormat;

impl ExecutableFormat for XbeFormat {
    fn name(&self) -> &'static str {
        "XBE"
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.starts_with(b"XBEH")
    }

    fn load(&self, data: &[u8]) -> Executable {
        // SAFETY: Assumes valid XBE, else can go kaboom.
        //         Don't go kaboom.
        unsafe { xbe::load_executable(data) }
    }
}

/// Parse an Xbox executable (XBE)..
///
/// # Arguments
///
/// * `data` - whole guest-executable input to sniff and parse.
///
/// # Returns
///
/// The parsed [`Executable`], or an empty one if parse failed.
pub fn parse_executable(data: &[u8]) -> Executable {
    parse_executable_with(&BUILTIN_FORMATS, data)
}

/// Runs the XboxRecomp2 recompiler ([`xbox_recomp2::run_with`])
/// using the defaults for OG (DirectX)box.
///
/// # Arguments
///
/// * `input` - recompiler config to load.
/// * `diag` - reports progress and diagnostics.
///
/// # Errors
///
/// See [`xbox_recomp2::run_with`] for Error list.
pub fn run(input: &Path, hash_funcs: Option<&[String]>, diag: &mut dyn Write) -> Result<(), RunError> {
    xbox_recomp2::run_with(input, BUILTIN_FORMATS.as_slice(), &XBOX, diag, hash_funcs)
}
