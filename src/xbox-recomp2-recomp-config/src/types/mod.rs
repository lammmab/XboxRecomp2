//! The structs used in recompiler config.

pub use address_map::AddressMap;
use derive_more::{From, Into};
pub use midasm_hook::MidAsmHook;
pub use optimization_hints::{OptimizationHints, X87StackEffect};
pub use optimizations::Optimizations;
pub use register::{Register, RegisterIndexError};
pub use speed_hacks::SpeedHacks;
use std::collections::{BTreeSet, HashMap};
pub use switch_table::SwitchTable;

pub mod address_map;
pub mod midasm_hook;
pub mod optimization_hints;
pub mod optimizations;
pub mod register;
pub mod speed_hacks;
pub mod switch_table;

/// The full recompiler configuration.
///
/// # Example
///
/// ```toml
/// [main]
/// file_path = "game.bin"
/// out_directory_path = "out/"
///
/// [optimizations]
/// enable = true
/// eliminate_dead_flags = false
///
/// [speed_hacks]
/// fast_trig = false
///
/// [[switch]]
/// register = "edx"
/// base = 0x1234
/// labels = [0x100, 0x200, 0x300]
///
/// [alias]
/// symbol_aliases = { "sub_3D3240" = "D3D_CommonSetDebugRegisters" }
///
/// [[midasm_hook]]
/// name = "OnLoad"
/// return = true
/// address = 0x8000
///
/// [fixes]
/// functions = [
///   { address = 0x1000, size = 0x50 },
///   { address = 0x1000, size = 0x80 },
/// ]
///
/// banned_addresses = [
///   { start = 0x3000, end = 0x3100 },
/// ]
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RecompilerConfig {
    // ── Derived ──────────────────────────────────────────────────────────────
    /// Directory of the config file, with a trailing path separator.
    /// Empty when the path has no separator.
    pub directory_path: Box<str>,

    // ── [main] ───────────────────────────────────────────────────────────────
    /// Path of .xbe, .exe, relative to `directory_path`
    pub file_path: Box<str>,

    /// Output directory, relative to `directory_path` or absolute.
    pub out_directory_path: Box<str>,

    /// Enables runtime diagnostics, e.g. out of reach switch statements.
    pub debug: bool,

    // ── [optimizations] ──────────────────────────────────────────────────────
    /// Which optimisation passes run.
    pub optimizations: Optimizations,

    // ── [speed_hacks] ────────────────────────────────────────────────────────
    /// Which speed hacks run.
    pub speed_hacks: SpeedHacks,

    // ── [optimization_hints] ─────────────────────────────────────────────────
    /// Stuff the optimisation passes can't work out alone.
    pub optimization_hints: OptimizationHints,

    // ── Top-level [[switch]] ─────────────────────────────────────────────────
    /// Switch tables set in configuration.
    pub switch_tables: AddressMap<SwitchTable>,

    // ── [alias] ──────────────────────────────────────────────────────────────
    /// Mappings of `emitted name` -> `chosen name`.
    /// Examples:
    ///
    /// - `sub_3D3240` -> `D3D_CommonSetDebugRegisters`
    /// - `_xstart` -> `EntryPoint`
    pub symbol_aliases: HashMap<String, String>,

    /// Mappings of `hashed bytes` -> `chosen name`.
    /// Examples:
    ///
    /// - `9f3c1a7be2d84a65c0b17e48d5a2f913` -> `CoolFunc`
    /// - `1cb0e9df767beafe9a73ecc216b9f80a` -> `StableMappingLol`
    pub hash_aliases: HashMap<String, String>,

    // ── [fixes] ──────────────────────────────────────────────────────────────
    /// Guest functions to recompile: `address` -> `size` (`fixes.functions`).
    pub functions: AddressMap<FunctionSize>,

    /// Game (guest) functions entirely replaced by hooks.
    pub function_hooks: BTreeSet<FunctionAddress>,

    /// Invalid instructions to treat as data: `data` -> `size`.
    pub invalid_instructions: AddressMap<InvalidInstructionSize>,

    /// Address ranges excluded from analysis: `start` -> `end`
    pub banned_addresses: AddressMap<FunctionAddress>,

    // ── Top-level [[midasm_hook]] ────────────────────────────────────────────
    /// MidAsm hooks, address -> hook.
    pub midasm_hooks: AddressMap<MidAsmHook>,
}

/// Address of guest function in virtual memory (RAM).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default, From, Into)]
#[into(u64)]
pub struct FunctionAddress(pub u32);

/// Size of a guest function in bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct FunctionSize(pub u32);

/// Size of encoded instructions to treat as data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct InvalidInstructionSize(pub u32);

impl RecompilerConfig {
    /// Returns whether `addr` falls inside any banned address range.
    ///
    /// # Arguments
    ///
    /// * `addr` - the guest address to test.
    ///
    /// # Returns
    ///
    /// Whether any configured range contains `addr`.
    pub fn is_address_range_banned(&self, addr: u32) -> bool {
        self.banned_addresses
            .iter()
            .any(|(start, end)| addr >= start.0 && addr <= end.0)
    }
}
