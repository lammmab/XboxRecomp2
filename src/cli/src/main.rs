//! Command-line entry point.
//!
//! ```text
//! xboxrecomp2 [<config TOML>]
//! xboxrecomp2 recompile <config TOML>
//! xboxrecomp2 stats <config TOML> [--json]
//! ```
//!
//! `x86_context.h` is always generated with the Xbox crate's default
//! context header.
//!
//! Exit codes:
//!
//! - `0`: success, help, or a non-file input path.
//! - `1`: any failure, reported on stderr.

use argh::FromArgs;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use xbox_recomp2::executable::ExecutableFormat;
use xbox_recomp2::stats;
use xbox_recomp2_xbox::{XBOX, XbeFormat, run as run_pipeline};

/// Formats supported out the box.
const FORMATS: [&dyn ExecutableFormat; 1] = [&XbeFormat];

/// x86-to-C++ recompiler.
#[derive(FromArgs)]
struct Cli {
    /// config TOML file
    #[argh(positional)]
    config: Option<PathBuf>,

    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    /// recompile from a config TOML
    Recompile(RecompileArgs),

    /// report one run's statistics without writing files
    Stats(StatsArgs),
}

fn parse_list(value: &str) -> Result<Vec<String>, String> {
    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

/// recompile from a config TOML
#[derive(FromArgs)]
#[argh(subcommand, name = "recompile")]
struct RecompileArgs {
    /// config TOML file
    #[argh(positional)]
    config: PathBuf,

    /// function names to get hashes for, separated by commas
    #[argh(option, from_str_fn(parse_list))]
    funcs: Option<Vec<String>>,
}

/// report one run's statistics without writing files
#[derive(FromArgs)]
#[argh(subcommand, name = "stats")]
struct StatsArgs {
    /// config TOML file
    #[argh(positional)]
    input: PathBuf,

    /// print the machine-readable report
    #[argh(switch)]
    json: bool,
}

fn main() {
    let cli: Cli = argh::from_env();
    exit(run(&cli));
}

/// Runs the parsed command line, returning the exit status.
fn run(cli: &Cli) -> i32 {
    match &cli.command {
        Some(Command::Stats(args)) => stats_command(args),
        Some(Command::Recompile(args)) => recompile(&args.config, args.funcs.as_deref()),
        None => match &cli.config {
            Some(config) => recompile(config, None),
            None => {
                print_help();
                0
            }
        },
    }
}

fn print_help() {
    if let Err(help) = Cli::from_args(&["xboxrecomp2"], &["--help"]) {
        print!("{}", help.output);
    }
}

fn recompile(input: &Path, hash_funcs: Option<&[String]>) -> i32 {
    if !is_regular_file(input) {
        return 0;
    }

    let mut stdout = BufWriter::new(io::stdout());
    let result = run_pipeline(input, hash_funcs, &mut stdout);
    let _ = stdout.flush();

    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn stats_command(args: &StatsArgs) -> i32 {
    let mut diag = io::stderr();

    match stats::collect(&args.input, &FORMATS, &XBOX, &mut diag) {
        Ok(report) => {
            let mut stdout = BufWriter::new(io::stdout());
            let rendered = if args.json {
                report.write_json(&mut stdout)
            } else {
                report.write_text(&mut stdout)
            };

            match rendered.and_then(|_| stdout.flush()) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("Error: {error}");
                    1
                }
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn is_regular_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}
