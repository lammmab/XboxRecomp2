//! The recompilation pipeline: [`Recompiler`], and its errors.
//!
//! A run goes through three stages, in this order:
//!
//! 1. Load: build the run.
//!    - [`Recompiler::load_input`]: from a config TOML.
//!    - [`Recompiler::from_input`]: from an already-loaded config and bytes.
//!
//! 2. Analyse: find the functions to recompile.
//!    - [`Recompiler::analyse`]: discover the recompilable functions.
//!    - [`Recompiler::rename_symbols`]: name the entry point `_xstart` and apply aliases.
//!
//! 3. Generate: produce the C++ file set.
//!    - [`Recompiler::recompile`]: write the files to disk.
//!    - [`Recompiler::generate_in_memory`]: keep the files in memory instead.
//!    - [`Recompiler::generate`]: the shared code behind both.

use crate::analysis::discover;
use crate::analysis::{Function, FunctionBody, FunctionGraph};
use crate::codegen::function::model::FunctionModel;
use crate::codegen::function::{FunctionScratch, build_function, write_function};
use crate::codegen::optimizations;
use crate::codegen::run_state::RunState;
use crate::config::{ConfigError, RecompilerConfig, load as load_config};
use crate::context_header::assemble_context_header;
use crate::decode::Decoder;
use crate::executable::{Executable, ExecutableFormat, parse_executable_with};
use crate::output::{DiskWriter, OutError, OutputWriter};
use crate::output::{GeneratedFileSet, MemoryWriter};
use crate::platform::GuestPlatform;
use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use xbox_recomp2_executable::GuestAddress64;
use zydis::Mnemonic;

use crate::analysis::masked_function_hash;
use crate::decode::DecodeBuffer;

/// Printed when the input binary is missing or empty.
const CONFIG_LOAD_FAILED_ERROR: &str = "Error: Failed to load config file.";
/// Functions per generated `x86_recomp.N.cpp` file.
/// TODO: Move this
const FUNCTIONS_PER_UNIT: usize = 256;
/// Prefix for log lines.
const LOG_BANNER: &str = "[XboxRecomp2]";
/// Print progress every 600 functions, and for the last one.
const PROGRESS_INTERVAL: usize = 600;

/// One recompilation run: the loaded executable, its config, and the
/// statistics it collects as it goes.
///
/// Call these in order:
///
/// - [`Recompiler::load_input`]
/// - [`Recompiler::analyse`]
/// - [`Recompiler::rename_symbols`]
/// - [`Recompiler::recompile`]
pub struct Recompiler<'a> {
    /// The parsed guest executable.
    pub executable: Executable,

    /// The loaded configuration.
    pub config: RecompilerConfig,

    /// The target platform, like Xbox.
    pub platform: &'a dyn GuestPlatform,

    /// The final body of `x86_context.h`.
    pub context_header: Vec<u8>,

    /// The discovered functions, in output (address) order.
    pub functions: Vec<Function>,

    /// The instructions to generate for each auto-discovered function.
    bodies: BTreeMap<GuestAddress64, FunctionBody>,

    /// References between functions, used for optimisation.
    function_graph: FunctionGraph,

    /// Instructions we couldn't recompile, in the order first seen.
    /// Printed after generation.
    pub inst_missing: Vec<String>,

    /// To avoid duplicates in [`Recompiler::inst_missing`].
    inst_missing_index: HashSet<String>,

    /// Functions which we may have analysed incorrectly.
    pub wrong_analyse: Vec<WrongAnalyse>,

    /// To avoid duplicates in [`Recompiler::wrong_analyse`].
    wrong_analyse_index: HashSet<WrongAnalyse>,

    /// Switch tables found by the last analysis.
    /// (Including config overrides)
    pub switch_tables_discovered: usize,

    /// Number of switch tables specified in the config.
    pub switch_tables_from_config: usize,

    /// Decoder used during code generation.
    decoder: Decoder,

    /// Decoder used during function discovery.
    analyse_decoder: Decoder,
}

/// Why a recompilation step failed.
#[derive(Debug, Error)]
pub enum RunError {
    /// Config or input loading failed.
    #[error(transparent)]
    Load(#[from] LoadError),

    /// Function discovery found nothing to recompile.
    #[error("{}", no_derivable_functions_message(path))]
    NoDerivableFunctions {
        /// The input whose discovery found nothing.
        path: PathBuf,
    },

    /// Discovery didn't produce a function at the executable's entry point.
    #[error(
        "{path}: entry point 0x{:X} has no generated function; check exclusion ranges or add its range to fixes.functions", .address.get()
    )]
    MissingEntryPoint {
        /// The input whose entry point is missing.
        path: PathBuf,
        /// The guest entry point address.
        address: GuestAddress64,
    },

    /// An `alias.symbol_aliases` entry gives a duplicate name.
    #[error("alias.symbol_aliases: duplicate name `{name}` at 0x{first:X} and 0x{second:X}")]
    DuplicateName {
        /// The name both symbols have.
        name: Box<str>,
        /// Address of the first symbol with `name`.
        first: u64,
        /// Address of the second symbol with `name`.
        second: u64,
    },

    /// An `alias.hash_aliases` key isn't valid hex, or is listed twice with different names.
    #[error("alias.hash_aliases: invalid or conflicting hash `{key}`")]
    InvalidHashAlias {
        /// The offending key.
        key: Box<str>,
    },

    /// Writing the output files failed.
    #[error(transparent)]
    Out(#[from] OutError),
}

/// Errors produced while loading a recompilation run.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The config file is unreadable or malformed.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// A file read during loading failed.
    #[error("{path}: {source}")]
    Io {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// The configured input binary is empty.
    #[error("input binary is empty: {path}")]
    EmptyInput {
        /// Path of the empty input binary.
        path: PathBuf,
    },
}

/// A function whose last instruction isn't a `jmp`, `ret` or `int3`.
///
/// Printed under `potential wrong analyse` after generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WrongAnalyse {
    /// The function's base address.
    pub base: u64,

    /// The last instruction's address.
    pub address: u64,
}

impl<'a> Recompiler<'a> {
    /// Loads a run from a config TOML and the binary it points to.
    ///
    /// Prints the banner and config warnings to `diag`.
    ///
    /// # Arguments
    ///
    /// - `input`: the config TOML.
    /// - `formats`: executable formats used to parse the binary.
    /// - `platform`: the target platform, like Xbox.
    /// - `diag`: receives log lines.
    ///
    /// # Returns
    ///
    /// A run ready for [`Recompiler::analyse`].
    ///
    /// # Errors
    ///
    /// A [`RunError::Load`] with:
    ///
    /// - [`LoadError::Io`]: the input binary can't be read.
    /// - [`LoadError::Config`]: the config is malformed.
    /// - [`LoadError::EmptyInput`]: the input binary is empty.
    ///
    /// [`RunError::Load`]: crate::RunError::Load
    pub fn load_input(
        input: &Path,
        formats: &[&dyn ExecutableFormat],
        platform: &'a dyn GuestPlatform,
        diag: &mut dyn Write,
    ) -> Result<Self, RunError> {
        let shown_path = input.to_string_lossy();
        let _ = writeln!(diag, "{LOG_BANNER} Init...");
        let _ = writeln!(diag, "{LOG_BANNER} Loading config file {shown_path}...");

        let loaded = load_config(input).map_err(LoadError::Config)?;
        for warning in &loaded.warnings {
            let _ = writeln!(diag, "{warning}");
        }

        let input_path = input_path_of(&loaded.config);
        let input = match fs::read(&input_path) {
            Ok(bytes) => bytes,
            Err(source) => {
                let _ = writeln!(diag, "{LOG_BANNER} {CONFIG_LOAD_FAILED_ERROR}");
                return Err(LoadError::Io {
                    path: input_path,
                    source,
                }
                .into());
            }
        };

        if input.is_empty() {
            let _ = writeln!(diag, "{LOG_BANNER} {CONFIG_LOAD_FAILED_ERROR}");
            return Err(LoadError::EmptyInput { path: input_path }.into());
        }

        Ok(Self::from_input(loaded.config, &input, formats, platform)?)
    }

    /// Builds a run from a config and executable bytes.
    ///
    /// # Arguments
    ///
    /// - `config`: the run configuration.
    /// - `input`: the guest executable's bytes; must not be empty.
    /// - `formats`: executable formats used to parse `input`.
    /// - `platform`: the target platform, like Xbox.
    ///
    /// # Returns
    ///
    /// A run ready for [`Recompiler::analyse`], with no functions or
    /// statistics yet.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::EmptyInput`] when `input` is empty.
    pub fn from_input(
        config: RecompilerConfig,
        input: &[u8],
        formats: &[&dyn ExecutableFormat],
        platform: &'a dyn GuestPlatform,
    ) -> Result<Self, LoadError> {
        if input.is_empty() {
            return Err(LoadError::EmptyInput {
                path: input_path_of(&config),
            });
        }

        Ok(Recompiler {
            executable: parse_executable_with(formats, input),
            platform,
            context_header: {
                let mut header = format!(
                    "#define X86_RECOMP_DEBUG {}\n#define X86_NONVOLATILE_MEMORY {}\n\
                     #define X86_SINGLE_THREAD_LOCKS_FROM 0x{:X}u\n\
                     #define X86_CHECK_SINGLE_THREAD_LOCKS {}\n",
                    u8::from(config.debug),
                    u8::from(config.speed_hacks.runs_nonvolatile_memory()),
                    config.speed_hacks.single_thread_locks_from().unwrap_or(0),
                    u8::from(config.speed_hacks.runs_check_single_thread_locks()),
                )
                .into_bytes();
                header.extend_from_slice(&assemble_context_header(&platform.context_overlay()));
                header
            },
            config,
            functions: Vec::new(),
            bodies: BTreeMap::new(),
            function_graph: FunctionGraph::default(),
            inst_missing: Vec::new(),
            inst_missing_index: HashSet::new(),
            wrong_analyse: Vec::new(),
            wrong_analyse_index: HashSet::new(),
            switch_tables_discovered: 0,
            switch_tables_from_config: 0,
            decoder: Decoder::new(),
            analyse_decoder: Decoder::new_compatibility_mode(),
        })
    }

    /// Finds the functions to recompile in the loaded executable.
    ///
    /// See `function-discovery.md` for the nitty-gritty details.
    ///
    /// # Arguments
    ///
    /// - `diag`: receives the analysis progress lines.
    pub fn analyse(&mut self, diag: &mut dyn Write) {
        self.switch_tables_from_config = self.config.switch_tables.len();

        let discovered = discover(
            &mut self.executable,
            &mut self.config,
            &self.analyse_decoder,
            diag,
        );

        self.functions = discovered.functions;
        self.bodies = discovered.bodies;
        self.function_graph = discovered.graph;
        self.switch_tables_discovered = discovered.switch_tables;
    }

    /// Returns the function references from the last [`Self::analyse`] call.
    pub fn function_graph(&self) -> &FunctionGraph {
        &self.function_graph
    }

    /// Returns the instructions analysis discovered for a function.
    ///
    /// # Arguments
    ///
    /// - `address`: the function's base address.
    ///
    /// # Returns
    ///
    /// The function, or [`None`].
    pub fn function_body(&self, address: u64) -> Option<&FunctionBody> {
        self.bodies.get(&GuestAddress64::from(address))
    }

    /// Runs [`Recompiler::analyse`], then [`Recompiler::rename_symbols`].
    /// Fails if there's nothing usable to generate.
    ///
    /// # Errors
    ///
    /// - [`RunError::NoDerivableFunctions`]: no functions were found.
    /// - [`RunError::MissingEntryPoint`]: no function starts at the entry point.
    /// - [`RunError::DuplicateName`]: another symbol or alias already has this name.
    pub(crate) fn analyse_requiring_functions(
        &mut self,
        input: &Path,
        diag: &mut dyn Write,
    ) -> Result<(), RunError> {
        self.analyse(diag);

        if self.functions.is_empty() {
            return Err(RunError::NoDerivableFunctions {
                path: input.to_path_buf(),
            });
        }

        let entry = self.executable.entry_point;
        if !self
            .functions
            .iter()
            .any(|function| function.base == self.executable.entry_point)
        {
            return Err(RunError::MissingEntryPoint {
                path: input.to_path_buf(),
                address: entry,
            });
        }

        self.rename_symbols()
    }

    /// Gives symbols their final names.
    ///
    /// - Entry point -> `_xstart`.
    /// - Then apply `alias.symbol_aliases`.
    ///
    /// # Returns
    ///
    /// [`Ok`] when all renamed.
    ///
    /// # Errors
    ///
    /// - [`RunError::DuplicateName`]: got a duplicate after aliasing.
    pub fn rename_symbols(&mut self) -> Result<(), RunError> {
        // Set name for entry point.
        if let Some(symbol) = self
            .executable
            .symbols
            .find_mut(self.executable.entry_point)
        {
            symbol.name = "_xstart".into();
        }

        // Figure out which functions match a hash alias
        let hash_renames = self.hash_alias_renames()?;

        // Apply the aliases.
        let aliases = &self.config.symbol_aliases;
        let mut manually_named: HashSet<u64> = HashSet::new();
        if !aliases.is_empty() {
            for symbol in self.executable.symbols.iter_mut() {
                if let Some(alias) = aliases.get(&*symbol.name) {
                    symbol.name = alias.as_str().into();
                    manually_named.insert(symbol.address.get());
                }
            }
        }

        // Apply hash alises. Manual aliases take precedence here.
        for (address, name) in hash_renames {
            if manually_named.contains(&address.get()) {
                continue;
            }
            if let Some(symbol) = self.executable.symbols.find_mut(address) {
                symbol.name = name.as_str().into();
            }
        }

        // Quick check for duplicate.
        let mut name_to_address: HashMap<&str, u64> =
            HashMap::with_capacity(self.executable.symbols.len());
        for symbol in self.executable.symbols.iter() {
            let address = symbol.address.get();
            let first = match name_to_address.insert(&symbol.name, address) {
                Some(first) => first,
                None => continue,
            };

            // If does not match first address, error.
            if first != address {
                return Err(RunError::DuplicateName {
                    name: symbol.name.clone(),
                    first,
                    second: address,
                });
            }
        }

        Ok(())
    }

    /// Prints the masked hash of input functions.
    ///
    /// # Arguments
    ///
    /// - `names`: symbol names (after aliasing), e.g. `sub_1A510` or `_xstart`.
    /// - `out`: receives one line per match.
    pub fn print_function_hashes(&self, names: &[String], out: &mut dyn Write) {
        let mut buffer = DecodeBuffer::new();
        let mut found: HashSet<&str> = HashSet::new();

        for function in &self.functions {
            let Some(symbol) = self.executable.symbols.find(function.base) else { continue };
            let Some(name) = names.iter().find(|n| n.as_str() == &*symbol.name) else { continue };

            match self.function_hash(function, &mut buffer) {
                Some(hash) => {
                    let _ = writeln!(out, "{name} 0x{:X} {hash:032x}", function.base.get());
                }
                None => {
                    let _ = writeln!(out, "{name}: could not hash (no readable bytes)");
                }
            }
            found.insert(name);
        }

        for name in names {
            if !found.contains(name.as_str()) {
                let _ = writeln!(out, "{name}: no function with this name");
            }
        }
    }

    /// Hashes a function's original bytes, ignoring per-link fields.
    ///
    /// # Arguments
    ///
    /// - `function`: the function to hash.
    /// - `buffer`: reusable decode storage.
    ///
    /// # Returns
    ///
    /// [`None`] if the function has no body or its bytes can't be read.
    fn function_hash(&self, function: &Function, buffer: &mut DecodeBuffer) -> Option<u128> {
        let body = self.bodies.get(&function.base)?;
        let data = self.executable.find(function.base.get())?;
        let base = self.executable.base.get() as u32;
        let image_range = base..base.wrapping_add(self.executable.size_of_image as u32);
        let addresses: Vec<u32> = body.starts().iter().map(|a| a.get()).collect();

        masked_function_hash(
            data,
            function.base.get() as u32,
            &addresses,
            &image_range,
            &self.analyse_decoder,
            buffer,
        )
    }

    /// Finds functions with a hash matching an `alias.hash_aliases` entry.
    ///
    /// # Returns
    ///
    /// The address and new name of each matching function.
    ///
    /// # Errors
    ///
    /// - [`RunError::InvalidHashAlias`]: a key isn't valid hex, or two keys
    ///  have a duplicate hash.
    fn hash_alias_renames(&self) -> Result<Vec<(GuestAddress64, String)>, RunError> {
        if self.config.hash_aliases.is_empty() {
            return Ok(Vec::new());
        }

        // Hex string -> u128
        let mut by_hash: HashMap<u128, &str> = HashMap::new();
        for (key, name) in &self.config.hash_aliases {
            let invalid = || RunError::InvalidHashAlias {
                key: key.as_str().into(),
            };

            let hex = key.trim().trim_start_matches("0x");
            let hash = u128::from_str_radix(hex, 16).map_err(|_| invalid())?;

            if let Some(previous) = by_hash.insert(hash, name) {
                if previous != name.as_str() {
                    return Err(invalid());
                }
            }
        }

        let mut buffer = DecodeBuffer::new();
        let mut renames = Vec::new();

        for function in &self.functions {
            let Some(hash) = self.function_hash(function, &mut buffer) else {
                continue;
            };

            if let Some(name) = by_hash.get(&hash) {
                renames.push((function.base, (*name).to_string()));
            }
        }

        Ok(renames)
    }

    /// Generates C++ for the analysed functions and writes it to disk:
    ///
    /// - `x86_config.h`
    /// - `x86_context.h`
    /// - `x86_recomp_shared.h`
    /// - `x86_func_mapping.cpp`
    /// - `x86_recomp.N.cpp`: the functions, 256 per file
    ///
    /// Files that haven't changed aren't rewritten.
    ///
    /// # Arguments
    ///
    /// - `diag`: receives the progress and diagnostic lines.
    ///
    /// # Errors
    ///
    /// - [`OutError::OutputPathIsSymlink`]: an output path is a symlink.
    /// - [`OutError::Io`]: a filesystem operation failed.
    pub fn recompile(&mut self, diag: &mut dyn Write) -> Result<(), OutError> {
        let mut writer = DiskWriter::new(&self.config)?;
        let mut no_mnemonics = |_: Mnemonic| ();
        self.generate(diag, &mut writer, &mut no_mnemonics)
    }

    /// Like [`Recompiler::recompile`], but keeps the files in memory.
    ///
    /// # Arguments
    ///
    /// - `diag`: receives progress and diagnostic lines.
    ///
    /// # Returns
    ///
    /// One `(file name, contents)` entry per file.
    ///
    /// # Errors
    ///
    /// Never fails.
    pub fn generate_in_memory(
        &mut self,
        diag: &mut dyn Write,
    ) -> Result<GeneratedFileSet, OutError> {
        let mut writer = MemoryWriter::new();
        let mut no_mnemonics = |_: Mnemonic| ();
        self.generate(diag, &mut writer, &mut no_mnemonics)?;
        Ok(writer.finish())
    }

    /// Generates every output file and passes each one to `writer`.
    /// Also collects stats.
    ///
    /// # Errors
    ///
    /// Returns [`OutError`] if [`DiskWriter`] fails to save a file.
    pub(crate) fn generate(
        &mut self,
        diag: &mut dyn Write,
        writer: &mut dyn OutputWriter,
        mnemonics: &mut dyn FnMut(Mnemonic),
    ) -> Result<(), OutError> {
        // Write the shared headers and function mapping.
        writer.write_config_header(&self.executable);
        writer.save(Some("x86_config.h"))?;

        writer.write_context_header(&self.context_header);
        writer.save(Some("x86_context.h"))?;

        writer.write_shared_header(&self.executable, &self.config);
        writer.save(Some("x86_recomp_shared.h"))?;

        writer.write_func_mapping(&self.executable);
        writer.save(Some("x86_func_mapping.cpp"))?;

        // Build every function first.
        // So we can optimize globally.
        let mut scratch = FunctionScratch::new();
        let mut models: Vec<FunctionModel> = self
            .functions
            .iter()
            .map(|function| {
                build_function(
                    &self.executable,
                    &self.config,
                    &self.decoder,
                    function,
                    self.bodies.get(&function.base),
                    &mut scratch,
                    diag,
                )
            })
            .collect();

        // Run optimisation passes.
        optimizations::run(
            &mut models,
            &self.function_graph,
            &self.executable.imports,
            &self.config.optimization_hints,
            &self.config.optimizations,
            &self.config.speed_hacks,
            diag,
        );

        // Write each function.
        let total = models.len();
        let mut body = Vec::new();

        for (index, model) in models.into_iter().enumerate() {
            // Start a new output file every FUNCTIONS_PER_UNIT functions.
            if index > 0 && index % FUNCTIONS_PER_UNIT == 0 {
                writer.save(None)?;
                writer.write_split_include();
            }

            // Report progress.
            if index % PROGRESS_INTERVAL == 0 || index == total - 1 {
                let percent = (index + 1) as f64 / total as f64 * 100.0;
                let _ = writeln!(diag, "Recompiling functions... {percent:.0}%");
            }

            // Write the function.
            body.clear();
            write_function(
                &self.executable,
                &self.config,
                self.platform,
                &model,
                &mut scratch,
                &mut RunState {
                    inst_missing: &mut self.inst_missing,
                    inst_missing_index: &mut self.inst_missing_index,
                    wrong_analyse: &mut self.wrong_analyse,
                    wrong_analyse_index: &mut self.wrong_analyse_index,
                    mnemonics: &mut *mnemonics,
                    diag,
                },
                &mut body,
            );
            writer.append_bytes(&body);
        }

        self.write_missing_diagnostics(diag);
        writer.save(None)
    }

    fn write_missing_diagnostics(&self, diag: &mut dyn Write) {
        if !self.inst_missing.is_empty() {
            let _ = writeln!(diag, "\nmissing following instructions:");
        }

        let mut count_jmp = 0;
        for name in &self.inst_missing {
            if count_jmp >= 2 {
                let _ = writeln!(diag, "{name}");
                count_jmp = 0;
            } else {
                let _ = write!(diag, "{name}, ");
                count_jmp += 1;
            }
        }

        let _ = writeln!(diag);

        if !self.wrong_analyse.is_empty() {
            let _ = writeln!(diag, "\npotential wrong analyse:");
        }

        for entry in &self.wrong_analyse {
            let WrongAnalyse { base, address } = *entry;
            let _ = writeln!(diag, "Base: 0x{base:x}, Address: 0x{address:x}");
        }

        let _ = writeln!(diag, "Potential wrong analyse {}", self.wrong_analyse.len());
    }
}

/// Returns the path of the config's input binary (exe/xbe).
fn input_path_of(config: &RecompilerConfig) -> PathBuf {
    PathBuf::from(format!("{}{}", config.directory_path, config.file_path))
}

/// Error message for [`RunError::NoDerivableFunctions`].
fn no_derivable_functions_message(path: &Path) -> String {
    format!(
        "no functions could be derived from {} by discovery; \
         provide an explicit functions list instead: a recompiler config \
         with `fixes.functions` entries, run through \
         `xboxrecomp2 recompile <config.toml>`",
        path.display()
    )
}
