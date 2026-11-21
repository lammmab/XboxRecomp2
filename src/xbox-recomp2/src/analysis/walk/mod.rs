//! Walk code reachable from a function entry without decoding unrelated bytes.
//!
//! From an entry, the walker:
//! - Decodes reachable instructions and follows local jumps.
//! - Saves calls for separate walks.
//! - Rewalks when new entries or jump targets appear.

use crate::analysis::graph::{
    Diagnostic, DiscoveryGraph, EdgeKind, FunctionDiscoverySource, FunctionNode, Instruction,
    LearnedTargets, LocalEdge, StopReason,
};
use crate::config::{AddressMap, FunctionAddress, FunctionSize, MidAsmHook, RecompilerConfig};
use crate::decode::{DecodeBuffer, DecodeOutcome, Decoder, RangeDecoder};
use crate::executable::Executable;
use code_reader::CodeReader;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
pub(in crate::analysis) use update::WalkUpdate;
use xbox_recomp2_executable::GuestAddress32;

mod blocks;
mod branches;
mod code_reader;
mod hooks;
#[cfg(test)]
mod transfer_tests;
mod update;

/// Walks functions in one executable and caches decoded instructions.
///
/// # Remarks
///
/// Create a new walker if bytes, sections, exclusions, function sizes, or hooks
/// change as a result of outside scans.
pub(in crate::analysis) struct FunctionWalker<'a> {
    executable: &'a Executable,
    config: &'a RecompilerConfig,
    reader: CodeReader<'a>,
    sizes: BTreeMap<GuestAddress32, FunctionSize>,
    hooks: AddressMap<MidAsmHook>,
    decoder: &'a Decoder,
    buffer: DecodeBuffer,
    cache: BTreeMap<GuestAddress32, Result<Arc<Instruction>, StopReason>>,
}

impl<'a> FunctionWalker<'a> {
    /// Makes a new walker.
    ///
    /// # Arguments
    ///
    /// - `executable`: code bytes and section mapping for this session.
    /// - `config`: exclusions, function sizes, and hooks for this session.
    /// - `decoder`: instruction decoder shared across walks.
    pub fn new(
        executable: &'a Executable,
        config: &'a RecompilerConfig,
        decoder: &'a Decoder,
    ) -> Self {
        Self {
            executable,
            config,
            reader: CodeReader::new(executable, config),
            sizes: config
                .functions
                .iter()
                .map(|(entry, size)| (GuestAddress32::from(entry.0), *size))
                .collect(),
            hooks: config.midasm_hooks.clone(),
            decoder,
            buffer: DecodeBuffer::new(),
            cache: BTreeMap::new(),
        }
    }

    /// Checks whether code bytes at this address are mapped and not excluded.
    ///
    /// # Arguments
    ///
    /// - `address`: possible function entry or reference target.
    pub fn is_executable_target(&self, address: GuestAddress32) -> bool {
        self.reader.window(address).is_ok()
    }

    /// Walks a single function.
    ///
    /// A walk involves:
    /// - Decoding reachable instructions.
    /// - Following local jumps and both paths of branches (e.g. `jz`).
    /// - Saving calls (`call`) and tail calls (`jmp`) for later checks.
    /// - Building [`BasicBlock`]s and noting why paths stop.
    /// - Adding referenced targets to the graph if they map to executable code.
    ///
    /// Walk again after learning new entries: a local jump may become a tail
    /// call. Configured sizes take precedence over sizes in the graph.
    ///
    /// # Arguments
    ///
    /// - `graph`: known functions and resolver findings; updated with this walk.
    /// - `entry`: entry of a function already in `graph`.
    ///
    /// # Returns
    ///
    /// The changes and newly seeded function entries, or `None` if `entry` is
    /// not in the graph.
    ///
    /// [`BasicBlock`]: crate::analysis::graph::BasicBlock
    pub fn walk_function(
        &mut self,
        graph: &mut DiscoveryGraph,
        entry: GuestAddress32,
    ) -> Option<WalkUpdate> {
        // Grab the existing function node from the graph.
        let old = graph.functions.get(&entry)?;
        let mut node = FunctionNode::new(entry);
        node.discovery_sources = old.discovery_sources.clone();
        node.authoritative_size = self.sizes.get(&entry).copied().or(old.authoritative_size);

        // Fill this function's body before adding referenced functions.
        self.walk_function_body(&mut node, &graph.functions, &old.learned);

        // Compare the nodes, then move saved targets into the replacement.
        let old = graph.functions.get_mut(&entry).unwrap();
        let mut update = WalkUpdate {
            changed: *old != node,
            new_functions: Vec::new(),
        };
        node.learned = core::mem::take(&mut old.learned);
        let func_references: Vec<_> = node.references.iter().copied().collect();
        *old = node;

        // Add the new references (functions) to the graph
        for reference in func_references {
            if !self.is_executable_target(reference.target) {
                continue;
            }
            if !graph.functions.contains_key(&reference.target) {
                update.new_functions.push(reference.target);
            }
            update.changed |= graph.add_function(
                reference.target,
                FunctionDiscoverySource::Reference {
                    function: entry,
                    site: reference.site,
                    kind: reference.kind,
                },
                None,
            );
        }

        update.new_functions.sort_unstable();
        update.new_functions.dedup();

        Some(update)
    }

    /// Builds the body reachable from this function's entry.
    ///
    /// - Follow local paths, saving instructions and stops.
    /// - Treat calls and jumps to other functions as references, not local paths.
    /// - Group the reached instructions into blocks.
    fn walk_function_body(
        &mut self,
        node: &mut FunctionNode,
        known_entries: &BTreeMap<GuestAddress32, FunctionNode>,
        learned: &LearnedTargets,
    ) {
        // Start with all function entries as pending addresses.
        // On first ever call, that would be `_xstart` (entry point)
        // and the kernel thunks. & Knuckles.
        let mut pending = BTreeSet::from([node.entry]);

        // Codegen writes out the whole `fixes.functions` range, even bits
        // nothing jumps to. So walk all of it, or we'd miss their calls.
        if let Some(size) = node.authoritative_size {
            self.queue_manual_range(node, size, known_entries, &mut pending);
        }

        let mut visited = BTreeSet::new();
        let mut edges = BTreeMap::<GuestAddress32, Vec<LocalEdge>>::new();
        while let Some(address) = pending.pop_first() {
            if !visited.insert(address) {
                continue;
            }

            // Get the instruction here, or note why this path stops.
            let result = self.get_or_decode_instruction(node, address);
            let instruction = match result {
                Ok(instruction) => instruction,
                Err(reason) => {
                    // Initial D(iagnostic)
                    // https://youtu.be/UcTJja9jVps?list=RDb78-Ml6GTzk
                    node.diagnostics.insert(Diagnostic { address, reason });
                    continue;
                }
            };

            // We have hooks, which are injected before the instructions.
            // These can crop up at any address; and call any new code
            // that would otherwise be unreachable.

            // Checking this on evern insn is kinda inefficient, but we kinda
            // gotta work with it, okay?
            let hook = self.hooks.get(FunctionAddress::from(address.get()));
            let instruction = if hook.is_some() {
                hooks::hooked(&instruction)
            } else {
                instruction
            };

            // If this is a branch, track all of the targets.
            // e.g. i.e. output all locations that `jmp`, could take you to.
            let mut local_edges = match hook {
                Some(hook) => {
                    hooks::local_successors(node, &instruction, hook, known_entries, learned)
                }
                None => branches::local_successors(node, &instruction, known_entries, learned),
            };

            // When the next address falls in excluded bytes, continue after
            // them. This includes a branch's not-taken path.
            //
            // e.g. If a range is banned in the config file because it's a
            //      sussy bakaka when the recompiler touches it.
            //
            // Jumps and taken branches keep their target for decoding later.
            local_edges.retain_mut(|edge| {
                if !matches!(
                    edge.kind,
                    EdgeKind::NextInstruction | EdgeKind::BranchNotTaken
                ) {
                    return true;
                }

                match self.reader.skip_excluded(edge.target) {
                    Ok(next_address) => {
                        edge.target = next_address;
                        true
                    }
                    Err(reason) => {
                        node.diagnostics.insert(Diagnostic {
                            address: edge.target,
                            reason,
                        });
                        false
                    }
                }
            });

            pending.extend(local_edges.iter().map(|edge| edge.target));
            edges.insert(address, local_edges);
            node.instructions.insert(address, instruction);
        }

        // Restore tail call -> local edge; function local.
        branches::reclassify_tail_calls_as_local_edges(node, &mut edges, learned);
        node.blocks = blocks::build(node, &edges, known_entries);
    }

    /// Queues every instruction in a manually sized function for walking.
    ///
    /// The size comes from `fixes.functions`.
    fn queue_manual_range(
        &mut self,
        node: &FunctionNode,
        size: FunctionSize,
        known_entries: &BTreeMap<GuestAddress32, FunctionNode>,
        pending: &mut BTreeSet<GuestAddress32>,
    ) {
        // Slice to end of file, and clamp the size to match.
        let data = self
            .executable
            .find(u64::from(node.entry.get()))
            .unwrap_or(&[]);
        let size = size.0.min(u32::try_from(data.len()).unwrap_or(u32::MAX));

        // Decode the data, same as codegen.
        let mut range = RangeDecoder::new(
            self.config,
            self.decoder,
            &mut self.buffer,
            data,
            node.entry,
            size,
        );
        while let Some(step) = range.next_step() {
            // Skip junk that won't decode, and other functions' entries.
            let other_function = known_entries.contains_key(&step.address)
                && branches::outside_body(node, step.address);

            if matches!(step.decoded, DecodeOutcome::Ok(_)) && !other_function {
                pending.insert(step.address);
            }
        }
    }

    /// Gets the instruction at `address`, decoding it if needed.
    ///
    /// Rejects instructions outside a configured function size or overlapping
    /// instructions already found in this function.
    fn get_or_decode_instruction(
        &mut self,
        node: &FunctionNode,
        address: GuestAddress32,
    ) -> Result<Arc<Instruction>, StopReason> {
        // Check instruction start for in-bounds.
        //
        // If a size is specified, the instruction may fall out of bounds,
        // thus not be allowed.
        let end = node
            .authoritative_size
            .map(|size| u64::from(node.entry.get()) + u64::from(size.0));

        if end.is_some_and(|end| address < node.entry || u64::from(address.get()) >= end) {
            // Note: Technically the `address < node.entry` case shouldn't ever
            //       fire; but juuuuust in case-
            return Err(StopReason::OutsideFunction);
        }

        // Grab the decode from cache if we have it.
        let instruction = self
            .cache
            .entry(address)
            .or_insert_with(|| {
                // Can we decode this?
                let window = self.reader.window(address)?;

                // So we can. Aight. Let's decode it mate.
                match self.buffer.decode_at(self.decoder, window, 0) {
                    DecodeOutcome::Ok(insn) => {
                        Ok(Arc::new(Instruction::from_decoded(address, insn)))
                    }
                    DecodeOutcome::Failed { .. } => Err(StopReason::DecodeFailed),
                }
            })
            .clone()?;

        // We also need to check the end of the decoded instruction.
        // The start fit, but the end may be out of range.
        if end.is_some_and(|end| instruction.end() > end) {
            return Err(StopReason::OutsideFunction);
        }

        // Make sure we don't overlap another instruction.
        let start = u64::from(address.get());
        let overlaps_previous = node
            .instructions
            .range(..address)
            .next_back() // get last
            .is_some_and(|(_, previous)| previous.end() > start);
        let overlaps_next = node
            .instructions
            .range(address..)
            .next() // get first
            .is_some_and(|(&next, _)| u64::from(next.get()) < instruction.end());

        if overlaps_previous || overlaps_next {
            return Err(StopReason::OverlappingInstruction);
        }

        Ok(instruction)
    }
}

#[cfg(test)]
mod tests {
    //! Check reachable paths and stopping points.
    use super::*;
    use crate::analysis::graph::test_helpers::{BASE, at, base, executable, function};
    use crate::config::{FunctionAddress, FunctionSize, InvalidInstructionSize, MidAsmHook};
    use crate::executable::{Section, SectionFlags};
    use rstest::rstest;

    #[derive(Clone, Copy)]
    enum Boundary {
        Section,
        Stored,
        ZeroFilled,
        File,
        Data,
        Banned,
        Invalid,
        Manual,
        InteriorBan,
        Limit,
    }

    // ── Core behaviour ───────────────────────────────────────────────────────

    #[test]
    fn walk_should_jump_across_a_gap_and_known_entry_into_another_section() {
        // The jump skips an unrelated known entry and lands in another code section.

        // Arrange
        // ```text
        // .text, file offset 0:
        // 0x1000: E9 FB 0F 00 00  jmp 0x2000 ; entry function
        // 0x1005: CC              int3       ; skipped
        // 0x1006: C3              ret        ; another function
        // 0x1007: CC              int3       ; skipped
        //
        // other, file offset 8:
        // 0x2000: C3              ret        ; another function in other section
        // ```
        let executable = code_sections(&[
            (BASE, &[0xe9, 0xfb, 0x0f, 0, 0, 0xcc, 0xc3, 0xcc]),
            (0x2000, &[0xc3]), // ret
        ]);
        let destination = GuestAddress32::from(0x2000);
        let config = RecompilerConfig::default();
        let decoder = Decoder::new_compatibility_mode();

        // Act
        let mut walker = FunctionWalker::new(&executable, &config, &decoder);
        let mut graph = DiscoveryGraph::default();
        graph.add_function(base(), FunctionDiscoverySource::EntryPoint, None);
        // Mark 0x1006 as another function's entry; the jump skips it.
        graph.add_function(at(6), FunctionDiscoverySource::Symbol, None);

        walker.walk_function(&mut graph, base()).unwrap();

        // Assert
        let node = &graph.functions[&base()];

        // The walk keeps only the jump and its destination, with a block at each.
        // Check we get instructions for both.
        assert_eq!(
            node.instructions.keys().copied().collect::<Vec<_>>(),
            [base(), destination]
        );
        // And blocks for both.
        assert_eq!(
            node.blocks
                .iter()
                .map(|block| block.start)
                .collect::<Vec<_>>(),
            [base(), destination]
        );

        // And make sure the data inside is sane.
        assert_eq!(node.block(base()).unwrap().start, base());
        assert_eq!(node.block(destination).unwrap().start, destination);
        assert!(node.block(at(6)).is_none());
        assert!(node.block(GuestAddress32::from(0x2001)).is_none());
        assert!(node.diagnostics.is_empty());

        // Note: 0x2000 is not marked as separate function, hence why it belongs
        //       to 0x1000 whiuch branches there.
    }

    // Map each byte slice to a code section at its guest address.
    fn code_sections(mappings: &[(u32, &[u8])]) -> Executable {
        let mut image = Executable {
            base: u64::from(BASE).into(),
            entry_point: u64::from(BASE).into(),
            ..Executable::default()
        };
        for (index, &(address, bytes)) in mappings.iter().enumerate() {
            let offset = image.data.len() as u32;
            let name = if index == 0 { ".text" } else { "other" };
            image.sections.push(Section::new(
                name,
                u64::from(address),
                bytes.len() as u32,
                SectionFlags::CODE,
                offset,
            ));
            image.data.extend_from_slice(bytes);
        }
        image.size = image.data.len() as u32;
        image
    }

    #[test]
    fn walk_should_report_ambiguity_when_target_overlaps_instruction() {
        // Arrange: the jump lands inside the mov's immediate.
        // ```text
        // 0x1000: B8 00 00 00 00  mov eax,0
        // 0x1005: EB FA           jmp 0x1001  ; not an instruction boundary
        // ```
        let node = function(&[0xb8, 0, 0, 0, 0, 0xeb, 0xfa]);

        // Act.
        let diagnostics = &node.diagnostics;

        // Assert.
        assert!(diagnostics.contains(&Diagnostic {
            address: at(1),
            reason: StopReason::OverlappingInstruction
        }));
    }

    #[rstest]
    #[case::section(&[0xb8, 1, 0, 0, 0], Boundary::Section, StopReason::DecodeFailed)]
    #[case::stored(&[0xb8, 1, 0, 0, 0], Boundary::Stored, StopReason::DecodeFailed)]
    #[case::zero_filled(&[0xc3], Boundary::ZeroFilled, StopReason::Unmapped)]
    #[case::file(&[0xb8], Boundary::File, StopReason::DecodeFailed)]
    #[case::data(&[0xc3], Boundary::Data, StopReason::NotExecutable)]
    #[case::banned(&[0xc3], Boundary::Banned, StopReason::Excluded)]
    #[case::invalid(&[0xc3], Boundary::Invalid, StopReason::Excluded)]
    #[case::manual(&[0xb8, 1, 0, 0, 0], Boundary::Manual, StopReason::OutsideFunction)]
    #[case::interior_ban(&[0xb8, 1, 0, 0, 0], Boundary::InteriorBan, StopReason::DecodeFailed)]
    #[case::address_limit(&[0xc3], Boundary::Limit, StopReason::Unmapped)]
    fn walk_should_report_stop_when_bytes_are_outside_allowed_range(
        #[case] code: &[u8],
        #[case] boundary: Boundary,
        #[case] reason: StopReason,
    ) {
        // Arrange: each case prevents decoding the entry instruction.
        // ```text
        // -------
        // section, stored, manual, interior_ban:
        // 0x1000: B8 01 00 00 00  mov eax,1
        //   section:      virtual section ends at 0x1001
        //   stored:       stored section bytes end at 0x1001
        //   manual:       configured function ends at 0x1001
        //   interior_ban: 0x1002 is excluded, truncating the decoder's window
        // -------
        // file:
        // 0x1000: B8              mov eax,imm32  ; incomplete: file ends here
        // -------
        // zero_filled, data, banned, invalid, address_limit:
        // 0x1000: C3              ret           ; byte supplied, but not decodable
        //   zero_filled:   section has no stored bytes
        //   data:          section is not executable
        //   banned:        0x1000 is excluded
        //   invalid:       invalid span [0x0FFF,0x1001) covers the entry
        //   address_limit: image ends at 0x1000, exclusively
        // ```
        let mut executable = executable(code);
        let mut config = RecompilerConfig::default();
        match boundary {
            Boundary::Section => executable.sections[0].size = 1,
            Boundary::Stored => executable.sections[0].raw_size = 1,
            Boundary::ZeroFilled => executable.sections[0].raw_size = 0,
            Boundary::File => executable.sections[0].size = 10,
            Boundary::Data => executable.sections[0].flags = SectionFlags::DATA,
            Boundary::Banned => config
                .banned_addresses
                .insert_or_overwrite(FunctionAddress(BASE), FunctionAddress(BASE)),
            Boundary::Invalid => config
                .invalid_instructions
                .insert_or_overwrite(FunctionAddress(BASE - 1), InvalidInstructionSize(2)),
            Boundary::Manual => config
                .functions
                .insert_or_overwrite(FunctionAddress(BASE), FunctionSize(1)),
            Boundary::InteriorBan => config
                .banned_addresses
                .insert_or_overwrite(FunctionAddress(BASE + 2), FunctionAddress(BASE + 2)),
            Boundary::Limit => executable.address_limit = Some(u64::from(BASE).into()),
        }
        let decoder = Decoder::new_compatibility_mode();
        let mut walker = FunctionWalker::new(&executable, &config, &decoder);
        let mut graph = DiscoveryGraph::default();
        graph.add_function(base(), FunctionDiscoverySource::Manual, None);

        // Act.
        walker.walk_function(&mut graph, base()).unwrap();

        // Assert.
        assert!(graph.functions[&base()].instructions.is_empty());
        assert!(graph.functions[&base()].diagnostics.contains(&Diagnostic {
            address: base(),
            reason
        }));
    }

    #[test]
    fn walk_should_report_stop_when_hook_target_is_excluded() {
        // Arrange:
        // ```text
        // 0x1000: 90  nop  ; hook jumps to 0x1002
        // 0x1001: C3  ret
        // 0x1002: C3  ret  ; banned byte
        // ```
        let executable = executable(&[0x90, 0xc3, 0xc3]);
        let mut config = RecompilerConfig::default();
        config.midasm_hooks.insert_or_overwrite(
            FunctionAddress(BASE),
            MidAsmHook {
                name: "watch".into(),
                jump_address: BASE + 2,
                ..MidAsmHook::default()
            },
        );
        config
            .banned_addresses
            .insert_or_overwrite(FunctionAddress(BASE + 2), FunctionAddress(BASE + 2));
        let decoder = Decoder::new_compatibility_mode();
        let mut walker = FunctionWalker::new(&executable, &config, &decoder);
        let mut graph = DiscoveryGraph::default();
        graph.add_function(base(), FunctionDiscoverySource::EntryPoint, None);

        // Act.
        walker.walk_function(&mut graph, base()).unwrap();

        // Assert
        let function = &graph.functions[&base()];
        assert!(function.diagnostics.contains(&Diagnostic {
            address: at(2),
            reason: StopReason::Excluded,
        }));
        assert_eq!(
            function.instructions.keys().copied().collect::<Vec<_>>(),
            [base()]
        );
    }

    // ── Edge cases ───────────────────────────────────────────────────────────

    #[rstest]
    #[case::fallthrough(&[0x90, 0x90], false)]
    #[case::not_taken(&[0x74, 8], false)]
    #[case::explicit_jump(&[0xeb, 0], true)]
    fn walk_should_skip_exclusions_only_when_flow_is_sequential(
        #[case] prefix: &[u8],
        #[case] stopped: bool,
    ) {
        // Adjacent invalid and banned ranges merge into one skipped span.

        // Arrange
        // ```text
        // fallthrough:
        // 0x1000: 90               nop
        // 0x1001: 90               nop
        //
        // not_taken:
        // 0x1000: 74 08            je 0x100A
        //
        // explicit_jump:
        // 0x1000: EB 00            jmp 0x1002
        //
        // Shared suffix:
        // 0x1002: CC               int3  ; invalid byte
        // 0x1003: CC               int3  ; banned byte
        // 0x1004: E8 01 00 00 00   call 0x100A
        // 0x1009: C3               ret
        // 0x100A: C3               ret
        // ```
        //
        // Basically,
        let mut code = prefix.to_vec();
        code.extend_from_slice(&[0xcc, 0xcc, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3]);
        let executable = executable(&code);
        let mut config = RecompilerConfig::default();

        // Ban the two int3(s)
        config
            .invalid_instructions
            .insert_or_overwrite(FunctionAddress(BASE + 2), InvalidInstructionSize(1));
        config
            .banned_addresses
            .insert_or_overwrite(FunctionAddress(BASE + 3), FunctionAddress(BASE + 3));

        let decoder = Decoder::new_compatibility_mode();
        let mut walker = FunctionWalker::new(&executable, &config, &decoder);
        let mut graph = DiscoveryGraph::default();
        graph.add_function(base(), FunctionDiscoverySource::EntryPoint, None);

        // Act.
        walker.walk_function(&mut graph, base()).unwrap();

        // Assert.
        let function = &graph.functions[&base()];
        assert_eq!(function.instructions.contains_key(&at(4)), !stopped);
        assert_eq!(graph.functions.contains_key(&at(10)), !stopped);
        assert_eq!(
            function.diagnostics.contains(&Diagnostic {
                address: at(2),
                reason: StopReason::Excluded,
            }),
            stopped
        );
        assert!(!function.instructions.contains_key(&at(2)));
        assert!(!function.instructions.contains_key(&at(3)));
    }
}
