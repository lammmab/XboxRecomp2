//! Reads the recompiler config from a TOML file.

use super::types::{
    FunctionAddress, FunctionSize, InvalidInstructionSize, Optimizations, SpeedHacks, SwitchTable,
    X87StackEffect,
};
use super::{ConfigError, LoadedConfig, MidAsmHook, RecompilerConfig, directory_of};
use core::str::from_utf8;
use serde::Deserialize;
use serde::de::Error as _;
use std::collections::HashMap;
use toml::{Table, Value};

/// The whole config file as serde reads it, before it becomes a
/// [`RecompilerConfig`].
#[derive(Deserialize)]
struct ConfigDocument {
    #[serde(default)]
    main: MainSection,

    #[serde(default)]
    optimizations: OptimizationsSection,

    #[serde(default)]
    speed_hacks: SpeedHacksSection,

    #[serde(default)]
    optimization_hints: OptimizationHintsSection,

    #[serde(default)]
    fixes: FixesSection,

    #[serde(default)]
    switch: Vec<SwitchTable>,

    #[serde(default)]
    alias: AliasesSection,

    #[serde(default)]
    midasm_hook: Vec<MidAsmHookEntry>,
}

/// The `[fixes]` section.
#[derive(Deserialize, Default)]
#[serde(default)]
struct FixesSection {
    functions: Vec<FunctionEntry>,
    function_hooks: Vec<u32>,
    invalid_instructions: Vec<InvalidInstructionEntry>,
    banned_addresses: Vec<BannedAddressEntry>,
}

/// The `[alias]` section.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct AliasesSection {
    symbol_aliases: HashMap<String, String>,
    hash_aliases: HashMap<String, String>,
}

/// The `[main]` section.
#[derive(Deserialize, Default)]
#[serde(default)]
struct MainSection {
    file_path: String,
    out_directory_path: String,
    debug: bool,
}

/// One `[[midasm_hook]]` entry.
#[derive(Deserialize)]
struct MidAsmHookEntry {
    address: u32,

    #[serde(flatten)]
    hook: MidAsmHook,
}

/// The `[optimization_hints]` section.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct OptimizationHintsSection {
    x87_stack_effects: Vec<X87StackEffectEntry>,
}

/// The `[optimizations]` section.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OptimizationsSection {
    enable: bool,
    eliminate_return_slot: bool,
    eliminate_stack_args: bool,
    trust_callee_returns: bool,
    optimize_x87: bool,
    optimize_mmx: bool,
    eliminate_dead_x87_status: bool,
    eliminate_dead_flags: bool,
    fuse_compare_branch: bool,
    find_ebp_frames: bool,
    idiv32_after_cdq: bool,
    find_string_direction: bool,
}

/// The `[speed_hacks]` section.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SpeedHacksSection {
    enable: bool,
    fast_trig: bool,
    fast_x87_status: bool,
    fast_x87_stack: bool,
    fast_x87_ffree: bool,
    fast_fscale: bool,
    fast_sse_status: bool,
    nonvolatile_stack: bool,
    plain_sse_memory: bool,
    nonvolatile_memory: bool,
    lazy_cmov_load: bool,
    native_sized_addresses: bool,
    rep_memmove_memset: bool,
    clobber_eflags_for_unknown_code: bool,
    stack_slots_in_locals: bool,
    plain_lock_release: bool,
    single_thread_locks_from: u32,
    check_single_thread_locks: bool,
}

/// A `fixes.banned_addresses` entry.
#[derive(Deserialize)]
struct BannedAddressEntry {
    start: u32,
    end: u32,
}

/// A `fixes.functions` entry.
#[derive(Deserialize)]
struct FunctionEntry {
    address: u32,
    size: u32,
}

/// A `fixes.invalid_instructions` entry.
#[derive(Deserialize)]
struct InvalidInstructionEntry {
    data: u32,
    size: u32,
}

/// An `optimization_hints.x87_stack_effects` entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X87StackEffectEntry {
    address: u32,
    stack_at_entry: u8,
    stack_at_exit: u8,
}

impl Default for OptimizationsSection {
    fn default() -> Self {
        let passes = Optimizations::default();
        Self {
            enable: passes.enabled,
            eliminate_return_slot: passes.eliminate_return_slot,
            eliminate_stack_args: passes.eliminate_stack_args,
            trust_callee_returns: passes.trust_callee_returns,
            optimize_x87: passes.optimize_x87,
            optimize_mmx: passes.optimize_mmx,
            eliminate_dead_x87_status: passes.eliminate_dead_x87_status,
            eliminate_dead_flags: passes.eliminate_dead_flags,
            fuse_compare_branch: passes.fuse_compare_branch,
            find_ebp_frames: passes.find_ebp_frames,
            idiv32_after_cdq: passes.idiv32_after_cdq,
            find_string_direction: passes.find_string_direction,
        }
    }
}

impl Default for SpeedHacksSection {
    fn default() -> Self {
        let hacks = SpeedHacks::default();
        Self {
            enable: hacks.enabled,
            fast_trig: hacks.fast_trig,
            fast_x87_status: hacks.fast_x87_status,
            fast_x87_stack: hacks.fast_x87_stack,
            fast_x87_ffree: hacks.fast_x87_ffree,
            fast_fscale: hacks.fast_fscale,
            fast_sse_status: hacks.fast_sse_status,
            nonvolatile_stack: hacks.nonvolatile_stack,
            plain_sse_memory: hacks.plain_sse_memory,
            nonvolatile_memory: hacks.nonvolatile_memory,
            lazy_cmov_load: hacks.lazy_cmov_load,
            native_sized_addresses: hacks.native_sized_addresses,
            rep_memmove_memset: hacks.rep_memmove_memset,
            clobber_eflags_for_unknown_code: hacks.clobber_eflags_for_unknown_code,
            stack_slots_in_locals: hacks.stack_slots_in_locals,
            plain_lock_release: hacks.plain_lock_release,
            single_thread_locks_from: hacks.single_thread_locks_from,
            check_single_thread_locks: hacks.check_single_thread_locks,
        }
    }
}

/// Parses config file `bytes`.
pub(super) fn load_bytes(for_display: &str, bytes: &[u8]) -> Result<LoadedConfig, ConfigError> {
    let text = from_utf8(bytes).map_err(|source| ConfigError::Parse {
        path: for_display.into(),
        source: Box::new(source),
    })?;

    // Check for old keys first from original XboxRecomp.
    // And throw errors to help ShadowRecomp and others migrate.
    let document: Table = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: for_display.into(),
        source: Box::new(source),
    })?;
    reject_legacy_keys(for_display, &document)?;

    let raw: ConfigDocument = toml::from_str(text).map_err(|source| ConfigError::Schema {
        path: for_display.into(),
        source: Box::new(source),
    })?;
    build(for_display, raw)
}

/// Fails on keys that were removed or moved.
/// Basically error on original XboxRecomp configs.
fn reject_legacy_keys(path: &str, document: &Table) -> Result<(), ConfigError> {
    if let Some(main) = document.get("main").and_then(Value::as_table) {
        if main.contains_key("switch_table_file_path") {
            return Err(deprecated_key(
                path,
                "main.switch_table_file_path".to_owned(),
                "removed; inline switch tables as top-level [[switch]] entries instead",
            ));
        }

        // Keys that moved out of `[main]`.
        let moved_main_keys = [
            ("fast_trig", "moved; set `speed_hacks.fast_trig` instead"),
            ("functions", "moved; write `fixes.functions` instead"),
            (
                "invalid_instructions",
                "moved; write `fixes.invalid_instructions` instead",
            ),
            (
                "banned_addresses",
                "moved; write `fixes.banned_addresses` instead",
            ),
        ];

        for (key, advice) in moved_main_keys {
            if main.contains_key(key) {
                return Err(deprecated_key(path, format!("main.{key}"), advice));
            }
        }
    }

    if document
        .get("optimizations")
        .and_then(Value::as_table)
        .is_some_and(|table| table.contains_key("fast_trig"))
    {
        return Err(deprecated_key(
            path,
            "optimizations.fast_trig".to_owned(),
            "moved; set `speed_hacks.fast_trig` instead",
        ));
    }

    if document
        .get("speed_hacks")
        .and_then(Value::as_table)
        .is_some_and(|table| table.contains_key("unwrapped_string_addresses"))
    {
        return Err(deprecated_key(
            path,
            "speed_hacks.unwrapped_string_addresses".to_owned(),
            "renamed; set `speed_hacks.native_sized_addresses` instead",
        ));
    }

    if let Some(entries) = document.get("switch").and_then(Value::as_array) {
        for (index, entry) in entries.iter().enumerate() {
            if entry
                .as_table()
                .is_some_and(|table| table.contains_key("r"))
            {
                return Err(deprecated_key(
                    path,
                    format!("switch[{index}].r"),
                    "removed; write `register` instead",
                ));
            }
        }
    }

    Ok(())
}

/// Turns the parsed file into a [`RecompilerConfig`] and collects warnings.
fn build(path: &str, raw: ConfigDocument) -> Result<LoadedConfig, ConfigError> {
    let mut config = RecompilerConfig {
        directory_path: directory_of(path).into(),
        file_path: raw.main.file_path.into(),
        out_directory_path: raw.main.out_directory_path.into(),
        debug: raw.main.debug,
        function_hooks: raw
            .fixes
            .function_hooks
            .into_iter()
            .map(FunctionAddress)
            .collect(),
        optimizations: Optimizations {
            enabled: raw.optimizations.enable,
            eliminate_return_slot: raw.optimizations.eliminate_return_slot,
            eliminate_stack_args: raw.optimizations.eliminate_stack_args,
            trust_callee_returns: raw.optimizations.trust_callee_returns,
            optimize_x87: raw.optimizations.optimize_x87,
            optimize_mmx: raw.optimizations.optimize_mmx,
            eliminate_dead_x87_status: raw.optimizations.eliminate_dead_x87_status,
            eliminate_dead_flags: raw.optimizations.eliminate_dead_flags,
            fuse_compare_branch: raw.optimizations.fuse_compare_branch,
            find_ebp_frames: raw.optimizations.find_ebp_frames,
            idiv32_after_cdq: raw.optimizations.idiv32_after_cdq,
            find_string_direction: raw.optimizations.find_string_direction,
        },
        speed_hacks: SpeedHacks {
            enabled: raw.speed_hacks.enable,
            fast_trig: raw.speed_hacks.fast_trig,
            fast_x87_status: raw.speed_hacks.fast_x87_status,
            fast_x87_stack: raw.speed_hacks.fast_x87_stack,
            fast_x87_ffree: raw.speed_hacks.fast_x87_ffree,
            fast_fscale: raw.speed_hacks.fast_fscale,
            fast_sse_status: raw.speed_hacks.fast_sse_status,
            nonvolatile_stack: raw.speed_hacks.nonvolatile_stack,
            plain_sse_memory: raw.speed_hacks.plain_sse_memory,
            nonvolatile_memory: raw.speed_hacks.nonvolatile_memory,
            lazy_cmov_load: raw.speed_hacks.lazy_cmov_load,
            native_sized_addresses: raw.speed_hacks.native_sized_addresses,
            rep_memmove_memset: raw.speed_hacks.rep_memmove_memset,
            clobber_eflags_for_unknown_code: raw.speed_hacks.clobber_eflags_for_unknown_code,
            stack_slots_in_locals: raw.speed_hacks.stack_slots_in_locals,
            plain_lock_release: raw.speed_hacks.plain_lock_release,
            single_thread_locks_from: raw.speed_hacks.single_thread_locks_from,
            check_single_thread_locks: raw.speed_hacks.check_single_thread_locks,
        },
        symbol_aliases: raw.alias.symbol_aliases,
        hash_aliases: raw.alias.hash_aliases,
        ..RecompilerConfig::default()
    };

    let mut seen_symbol_aliases: HashMap<&str, &str> = HashMap::new(); // alias -> key
    for (key, alias) in &config.symbol_aliases {
        if let Some(prev) = seen_symbol_aliases.insert(alias.as_str(), key.as_str()) {
            // No two symbols can have the same emitted name.
            // Either we catch it here, or it becomes a compiler error later.
            return Err(ConfigError::Schema {
                path: path.into(),
                source: Box::new(toml::de::Error::custom(format!(
                    "alias.symbol_aliases: alias `{alias}` is used by both `{prev}` and `{key}`"
                ))),
            });
        }
    }

    let mut seen_hash_aliases: HashMap<&str, &str> = HashMap::new(); // alias -> key
    for (key, alias) in &config.hash_aliases {
        if let Some(prev) = seen_hash_aliases.insert(alias.as_str(), key.as_str()) {
            // No two hashes can have the same emitted name.
            // Either we catch it here, or it becomes a compiler error later.
            return Err(ConfigError::Schema {
                path: path.into(),
                source: Box::new(toml::de::Error::custom(format!(
                    "alias.hash_aliases: alias `{alias}` is used by both `{prev}` and `{key}`"
                ))),
            });
        }
    }

    for entry in raw.fixes.functions {
        config.functions.insert_or_overwrite(
            FunctionAddress::from(entry.address),
            FunctionSize(entry.size),
        );
    }

    for entry in raw.fixes.invalid_instructions {
        config.invalid_instructions.insert_or_overwrite(
            FunctionAddress::from(entry.data),
            InvalidInstructionSize(entry.size),
        );
    }

    for entry in raw.fixes.banned_addresses {
        config.banned_addresses.insert_or_overwrite(
            FunctionAddress::from(entry.start),
            FunctionAddress::from(entry.end),
        );
    }

    for entry in raw.optimization_hints.x87_stack_effects {
        config
            .optimization_hints
            .x87_stack_effects
            .insert_or_overwrite(
                FunctionAddress::from(entry.address),
                X87StackEffect {
                    stack_at_entry: entry.stack_at_entry,
                    stack_at_exit: entry.stack_at_exit,
                },
            );
    }

    for (index, table) in raw.switch.into_iter().enumerate() {
        let key = u32::try_from(table.base).map_err(|_| ConfigError::Schema {
            path: path.into(),
            source: Box::new(toml::de::Error::custom(format!(
                "switch[{index}].base does not fit in 32 bits"
            ))),
        })?;

        config
            .switch_tables
            .insert_or_overwrite(FunctionAddress::from(key), table);
    }

    let warnings = build_midasm_hooks(raw.midasm_hook, &mut config);

    Ok(LoadedConfig { config, warnings })
}

/// Builds the error for an old key found in the file at `path`.
fn deprecated_key(path: &str, field: String, advice: &'static str) -> ConfigError {
    ConfigError::DeprecatedKey {
        path: path.into(),
        field: field.into(),
        advice,
    }
}

/// Adds each `[[midasm_hook]]` entry to `config`.
fn build_midasm_hooks(
    entries: Vec<MidAsmHookEntry>,
    config: &mut RecompilerConfig,
) -> Vec<Box<str>> {
    let mut warnings = Vec::new();

    for entry in entries {
        let hook = entry.hook;

        if (hook.ret && hook.jump_address != 0)
            || (hook.return_on_true && hook.jump_address_on_true != 0)
            || (hook.return_on_false && hook.jump_address_on_false != 0)
        {
            warnings.push(format!("{}: can't return and jump at the same time", hook.name).into());
        }

        if (hook.ret || hook.jump_address != 0)
            && (hook.return_on_false
                || hook.return_on_true
                || hook.jump_address_on_false != 0
                || hook.jump_address_on_true != 0)
        {
            warnings.push(
                format!(
                    "{}: can't mix direct and conditional return/jump",
                    hook.name
                )
                .into(),
            );
        }

        config
            .midasm_hooks
            .insert_or_overwrite(FunctionAddress::from(entry.address), hook);
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::load_bytes;
    use crate::{ConfigError, LoadedConfig};
    use indoc::{formatdoc, indoc};
    use rstest::rstest;

    // ── Optimizations and speed hacks ───────────────────────────────────────

    #[rstest]
    #[case::optimizations("optimizations")]
    #[case::speed_hacks("speed_hacks")]
    fn switches_should_report_schema_error_when_key_is_unknown(#[case] section: &str) {
        // Arrange
        let content = format!("[{section}]\nunknown_setting = false");

        // Act
        let result = parse(&content);

        // Assert
        assert!(schema_error(&result).contains("unknown_setting"));
    }

    // ── Function overrides ───────────────────────────────────────────────────

    #[rstest]
    #[case::omitted("", &[])]
    #[case::addresses(
        "[fixes]\nfunction_hooks = [0x11040, 0x12000, 0x11040]",
        &[0x11040, 0x12000]
    )]
    fn overrides_should_collect_unique_guest_addresses(
        #[case] content: &str,
        #[case] expected: &[u32],
    ) {
        // Act
        let loaded = parse(content).unwrap();

        // Assert
        // Addresses are sorted, without duplicates, and not banned.
        let addresses: Vec<_> = loaded
            .config
            .function_hooks
            .iter()
            .map(|address| address.0)
            .collect();
        assert_eq!(addresses, expected);
        assert!(loaded.config.banned_addresses.is_empty());
    }

    #[rstest]
    #[case::too_large("0x100000000")]
    #[case::negative("-1")]
    fn overrides_should_reject_invalid_guest_addresses(#[case] address: &str) {
        // Arrange
        // Use an address outside the Xbox's 32-bit address range.
        let content = format!("[fixes]\nfunction_hooks = [{address}]");

        // Act
        let result = parse(&content);

        // Assert
        assert!(matches!(result, Err(ConfigError::Schema { .. })));
    }

    // ── Hooks, registers and legacy keys ─────────────────────────────────────

    #[rstest]
    #[case::main("[main]\nfast_trig = true", "main.fast_trig")]
    #[case::optimizations("[optimizations]\nfast_trig = true", "optimizations.fast_trig")]
    fn fast_trig_should_report_move_when_outside_speed_hacks(
        #[case] content: &str,
        #[case] field: &str,
    ) {
        // Act
        let result = parse(content);

        // Assert
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("cfg/recomp.toml: {field}: moved; set `speed_hacks.fast_trig` instead")
        );
    }

    #[test]
    fn eflags_and_unknown_switch_register_names_reject() {
        for name in ["eflags", "zzz"] {
            let content = formatdoc! {r#"
                [[switch]]
                register = "{name}"
                base = 0x1000
                labels = [1]
            "#};
            assert!(
                schema_error(&parse(&content))
                    .contains(&format!("unknown register '{name}'; expected 'eax'..'esp'")),
                "register = {name}"
            );
        }
    }

    #[test]
    fn hooks_with_return_and_jump_warn() {
        // You can't have both at the same time.
        // So we should warn.
        let content = r#"
        [[midasm_hook]]
        name = "Both"
        return = true
        jump_address = 0x100
        address = 0x1000

        [[midasm_hook]]
        name = "Mixed"
        jump_address = 0x200
        return_on_true = true
        address = 0x2000
    "#;
        let loaded = parse(content).unwrap();

        assert_eq!(
            loaded.warnings,
            vec![
                "Both: can't return and jump at the same time".into(),
                "Mixed: can't mix direct and conditional return/jump".into(),
            ]
        );
    }

    /// Schema errors start with the config file's path.
    #[test]
    fn schema_errors_carry_the_config_path() {
        let result = parse(indoc! {r#"
            [[switch]]
            register = "ebx"
        "#});
        match &result {
            Err(ConfigError::Schema { path, .. }) => assert_eq!(&**path, "cfg/recomp.toml"),
            other => panic!("expected Schema, got {other:?}"),
        }
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("cfg/recomp.toml:")
        );
    }

    /// Tests that no symbol or hash aliases can have duplicated emitted names.
    #[test]
    fn aliases_no_duplicates() {
        let result = parse(indoc! {r#"
            [alias]
            symbol_aliases = {
                sub_3D3240 = "D3D_CommonSetDebugRegisters",
                sub_3D3241 = "D3D_CommonSetDebugRegisters"
            }
            hash_aliases = {
                9f3c1a7be2d84a65c0b17e48d5a2f913 = "GetSnubbed",
                1cb0e9df767beafe9a73ecc216b9f80a = "GetSnubbed"
            }
        "#});

        let Err(err) = result else {
            panic!("duplicate alias should be rejected");
        };

        let msg = err.to_string();
        // Symbol
        assert!(msg.contains("D3D_CommonSetDebugRegisters"), "{msg}");
        assert!(msg.contains("sub_3D3240"), "{msg}");
        assert!(msg.contains("sub_3D3241"), "{msg}");
        // Hash
        assert!(msg.contains("GetSnubbed"), "{msg}");
        assert!(msg.contains("9f3c1a7be2d84a65c0b17e48d5a2f913"), "{msg}");
        assert!(msg.contains("1cb0e9df767beafe9a73ecc216b9f80a"), "{msg}");
    }

    /// Checks that `result` is a schema error and returns its message.
    fn schema_error(result: &Result<LoadedConfig, ConfigError>) -> String {
        match result {
            Err(error @ ConfigError::Schema { .. }) => error.to_string(),
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    /// Parses `content` as if it came from `cfg/recomp.toml`.
    fn parse(content: &str) -> Result<LoadedConfig, ConfigError> {
        load_bytes("cfg/recomp.toml", content.as_bytes())
    }
}
