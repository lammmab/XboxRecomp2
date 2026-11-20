//! Find the guest functions to recompile.
//!
//! - [`FunctionGraph`]: references between functions.
//! - [`FunctionBody`]: one function's instructions.
//!
//! See `doc/docs/function-discovery.md` for the full walkthrough.

use crate::analysis::switch_tables::discover_switch_tables;
use crate::config::{FunctionAddress, RecompilerConfig};
use crate::decode::Decoder;
use crate::executable::{Executable, Symbol, SymbolType};
pub use finalize::{
    BodyEdge, EdgeKind, Function, FunctionBody, FunctionGraph, FunctionReference, LocalTargets,
    ReferenceKind,
};
use graph::DiscoveryGraph;
pub(crate) use graph::{
    BruteForceKind, FunctionDiscoverySource, ReferenceKind as DiscoveryReferenceKind,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use walk::FunctionWalker;
use xbox_recomp2_executable::{GuestAddress32, GuestAddress64};

mod diagnostics;
mod fallback;
mod finalize;
mod graph;
mod pointer_tables;
mod reachable;
mod reader;
mod switch_tables;
mod walk;

/// Output of one discovery run over an executable.
pub(crate) struct Discovery {
    pub functions: Vec<Function>,
    pub bodies: BTreeMap<GuestAddress64, FunctionBody>,
    pub graph: FunctionGraph,
    pub switch_tables: usize,
}

/// Finds guest code to recompile.
///
/// # Remarks
///
/// The fallback/brute force scans can mistake data for code.
///
/// That's harmless, but it makes compiles slower and the binary larger,
/// so we try to keep it rare.
pub(crate) fn discover(
    executable: &mut Executable,
    config: &mut RecompilerConfig,
    decoder: &Decoder,
    diag: &mut dyn Write,
) -> Discovery {
    let _ = writeln!(diag, "\nSearching for functions...");

    // Okay.
    let manual_tables: BTreeSet<GuestAddress32> = get_switch_tables_from_config(config).collect();

    // Do the first initial scan.
    // This covers:
    // - Following calls and jumps.
    // - Following configured switch tables and discovering immediate pointers.
    let mut graph = DiscoveryGraph::default();
    add_known_functions(executable, config, decoder, &mut graph);
    reachable::expand(executable, config, decoder, &mut graph);
    let from_roots: BTreeSet<GuestAddress32> = graph.functions.keys().copied().collect();

    // Whole-section scans are a safety net, not the source of function boundaries.
    let mut discovered_tables: BTreeSet<GuestAddress32> = BTreeSet::new();
    for table in discover_switch_tables(executable) {
        let key = FunctionAddress(table.base as u32);
        discovered_tables.insert(GuestAddress32::from(key.0));
        if config.switch_tables.get(key).is_none() {
            config.switch_tables.insert_or_overwrite(key, table);
        }
    }

    // Use the brute force methods to gether more matches.
    fallback::collect(executable, config, decoder, &mut graph);

    // And repeat initial scans, to fill up the function graph references.
    reachable::expand(executable, config, decoder, &mut graph);
    discovered_tables
        .extend(get_switch_tables_from_config(config).filter(|site| !manual_tables.contains(site)));

    let (functions, bodies) = finalize::functions(config, &graph, diag);

    // Print the damn stats. The Hedgehog!
    diagnostics::report(&graph, &from_roots, diag);
    executable
        .symbols
        .insert_batch(functions.iter().map(|function| {
            Symbol::function(
                format!("sub_{:X}", function.base.get()),
                function.base.get(),
                function.size,
            )
        }));
    let _ = writeln!(diag, "Analysed {} functions.", functions.len());

    let references = FunctionGraph::from_discovery(graph);
    Discovery {
        functions,
        bodies,
        graph: references,
        switch_tables: discovered_tables.len(),
    }
}

/// Adds:
/// - The entry point and function symbols in executable code.
/// - Configured functions with their explicit sizes.
fn add_known_functions(
    executable: &Executable,
    config: &RecompilerConfig,
    decoder: &Decoder,
    graph: &mut DiscoveryGraph,
) {
    let walker = FunctionWalker::new(executable, config, decoder);

    // Add the entry point.
    if let Ok(entry) = GuestAddress32::try_from(executable.entry_point)
        && walker.is_executable_target(entry)
    {
        graph.add_function(entry, FunctionDiscoverySource::EntryPoint, None);
    }

    // Add all pre-existing functions from config file.
    for (address, size) in config.functions.iter() {
        graph.add_function(
            GuestAddress32::from(address.0),
            FunctionDiscoverySource::Manual,
            Some(*size),
        );
    }

    // Add function symbols:
    // - Imported functions. (kernel thunks, import table, etc.)
    // - Other symbols in executable code.
    for symbol in executable
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolType::Function)
    {
        if let Ok(address) = GuestAddress32::try_from(symbol.address)
            && walker.is_executable_target(address)
        {
            graph.add_function(address, FunctionDiscoverySource::Symbol, None);
        }
    }
}

fn get_switch_tables_from_config(
    config: &RecompilerConfig,
) -> impl Iterator<Item = GuestAddress32> + '_ {
    config
        .switch_tables
        .iter()
        .map(|(site, _)| GuestAddress32::from(site.0))
}

#[cfg(test)]
mod tests {
    //! Exercise discovery across direct, indirect, and fallback passes.

    use super::*;
    use crate::analysis::graph::test_helpers::{BASE, executable};
    use crate::config::FunctionSize;
    use rstest::rstest;

    #[rstest]
    #[case::automatic(false)]
    #[case::manual(true)]
    fn discovery_should_include_register_only_target_when_manually_configured(
        #[case] manual: bool,
    ) {
        // Only the padding scan finds +0x10. The register-only callee needs an
        // explicit entry because it has no padding or callback prologue.
        //
        // ```text
        // 1000: C3                       ret
        // 1010: B8 27 10 00 00 FF D0 C3  mov eax,0x1027; call eax; ret
        // 1027: C3                       ret
        // ```
        let mut code = [0xcc; 0x28];
        code[0] = 0xc3;
        code[0x10..0x18].copy_from_slice(&[0xb8, 0x27, 0x10, 0, 0, 0xff, 0xd0, 0xc3]);
        code[0x27] = 0xc3;
        let mut image = executable(&code);
        let mut config = RecompilerConfig::default();
        if manual {
            config
                .functions
                .insert_or_overwrite(FunctionAddress(BASE + 0x27), FunctionSize(1));
        }

        // Act.
        let discovery = discover(
            &mut image,
            &mut config,
            &Decoder::new_compatibility_mode(),
            &mut Vec::new(),
        );

        // Assert.
        assert!(
            discovery
                .bodies
                .contains_key(&GuestAddress64::from(u64::from(BASE + 0x10)))
        );
        assert_eq!(
            discovery
                .functions
                .iter()
                .any(|function| function.base.get() == u64::from(BASE + 0x27)),
            manual
        );
        assert!(discovery.graph.incoming((BASE + 0x27).into()).is_empty());
    }

    #[rstest]
    #[case::reached_instruction_start(&[0xeb, 0x0e], None, false)]
    #[case::inside_reached_operand(&[0xeb, 0x0b], None, false)]
    #[case::gap_skipped_by_jump(&[0xeb, 0x1e], None, true)]
    #[case::inside_configured_range(&[0xc3], Some(0x21), false)]
    #[case::at_configured_range_end(&[0xc3], Some(0x10), true)]
    fn discovery_should_filter_padding_starts_by_covered_bytes(
        #[case] entry: &[u8],
        #[case] manual_size: Option<u32>,
        #[case] expected: bool,
    ) {
        // Arrange: We start at 0x1000
        //
        // ```text
        // 0x1000: EB 1E           jmp 0x1020     ─────────────────────────┐
        //         EB 0E           jmp 0x1010     ───────────────────┐     │
        //         EB 0B           jmp 0x100D     ─────────────┐     │     │
        //         C3              ret                         │     │     │
        // 0x100D: B8 CC CC 90 90  mov eax, 0x9090CCCC    ◀───┘     │     │
        // 0x1010: 90 90 C3        nop; nop; ret          ◀─────────┘     │
        // 0x1020: C3              ret                    ◀───────────────┘
        // ```
        // The CC CC before 0x1010 suggests a new function.
        // We accept it, but only if the not already in existing function.
        // Which depends on where the branch landed.
        let mut code = [0xcc; 0x21];
        code[..entry.len()].copy_from_slice(entry);
        code[0x0d] = 0xb8;
        code[0x10..0x13].copy_from_slice(&[0x90, 0x90, 0xc3]);
        code[0x20] = 0xc3;
        let mut image = executable(&code);
        let mut config = RecompilerConfig::default();
        if let Some(size) = manual_size {
            config
                .functions
                .insert_or_overwrite(BASE.into(), FunctionSize(size));
        }

        // Act.
        let discovery = discover(
            &mut image,
            &mut config,
            &Decoder::new_compatibility_mode(),
            &mut Vec::new(),
        );

        // Assert
        assert_eq!(
            discovery
                .graph
                .functions()
                .any(|entry| entry.get() == BASE + 0x10),
            expected
        );
        assert_eq!(
            discovery
                .functions
                .iter()
                .any(|f| f.base.get() == u64::from(BASE + 0x10)),
            expected
        );
    }

    #[rstest]
    #[case::return_only(&[0xC3], &[(BASE as u64, 1)])]
    #[case::call_and_return(
        &[0xE8, 1, 0, 0, 0, 0xC3, 0xC3],
        &[(BASE as u64, 6), (BASE as u64 + 6, 1)]
    )]
    #[case::local_loop(&[0xEB, 0xFE], &[(BASE as u64, 2)])]
    fn discovery_should_follow_direct_flow(#[case] code: &[u8], #[case] expected: &[(u64, u64)]) {
        // Arrange:
        //
        // ```text
        // return_only:
        //   0x1000: C3              ret         ; one 1-byte function
        // call_and_return:
        //   0x1000: E8 01 00 00 00  call 0x1006 ; separate called function
        //   0x1005: C3              ret         ; caller ends at 0x1006 (exclusive)
        //   0x1006: C3              ret
        // local_loop:
        //   0x1000: EB FE           jmp 0x1000  ; local edge, not another function
        // ```
        let mut image = executable(code);
        let mut config = RecompilerConfig::default();
        let decoder = Decoder::new_compatibility_mode();

        // Act.
        let functions = discover(&mut image, &mut config, &decoder, &mut Vec::new()).functions;

        // Assert.
        assert_eq!(
            functions
                .iter()
                .map(|function| (function.base.get(), function.size))
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[rstest]
    #[case::reachable_call(0, None)]
    #[case::fallback_call(0x20, None)]
    #[case::manual_range_call(0, Some(0x13))]
    fn discovery_should_preserve_explicit_targets_when_padding_is_covered(
        #[case] call_site: usize,
        #[case] manual_size: Option<u32>,
    ) {
        // Arrange:
        //
        // ```text
        // reachable_call / manual_range_call:
        //   0x1000: E8 0B 00 00 00  call 0x1010
        //   0x1005: C3              ret
        //   0x1010: 90 90 C3        nop; nop; ret
        //
        // fallback_call:
        //   0x1000: EB 0E           jmp 0x1010
        //   0x1010: 90 90 C3        nop; nop; ret
        //   0x1020: E8 EB FF FF FF  call 0x1010
        //   0x1025: C3              ret
        // ```
        // In fallback_call, the jump skips the call at 0x1020. A later scan
        // still finds that call to 0x1010.
        //
        // In manual_range_call, the configured function at 0x1000 already
        // covers 0x1010. Padding alone cannot suggest a new function there,
        // but the call keeps 0x1010 as a separate function.
        let mut code = [0xcc; 0x26];
        code[..2].copy_from_slice(&[0xeb, 0x0e]);
        code[call_site] = 0xe8;
        code[call_site + 1..call_site + 5]
            .copy_from_slice(&(0x10i32 - call_site as i32 - 5).to_le_bytes());
        code[call_site + 5] = 0xc3;
        code[0x10..0x13].copy_from_slice(&[0x90, 0x90, 0xc3]);
        let mut image = executable(&code);
        let mut config = RecompilerConfig::default();
        if let Some(size) = manual_size {
            config
                .functions
                .insert_or_overwrite(BASE.into(), FunctionSize(size));
        }

        // Act.
        let discovery = discover(
            &mut image,
            &mut config,
            &Decoder::new_compatibility_mode(),
            &mut Vec::new(),
        );

        // Assert.
        assert!(
            discovery
                .functions
                .iter()
                .any(|f| f.base.get() == u64::from(BASE + 0x10))
        );
    }
}
