use crate::decode::{DecodeBuffer, DecodeOutcome, Decoder};
use core::ops::Range;
use xxhash_rust::xxh3::xxh3_128;

/// Hashes a function's bytes with per-link information discarded.
///
/// A per-link heuristic can be wrong (e.g. a constant that equals a valid
/// image address), but in practice that only loses a little distinguishability.
///
/// # Arguments
///
/// - `data`: original image bytes, starting at `entry`.
/// - `entry`: address of the function.
/// - `instructions`: start address of every instruction in the function.
/// - `image_range`: addresses that look like they point into the image.
/// - `decoder`: decoder for guest instructions.
/// - `buffer`: reusable decode storage.
///
/// # Returns
///
/// `None` if the function has no instructions or the bytes couldn't be read.
pub(crate) fn masked_function_hash( 
    data: &[u8],
    entry: u32,
    instructions: &[u32],
    image_range: &Range<u32>,
    decoder: &Decoder,
    buffer: &mut DecodeBuffer,
) -> Option<u128> {
    // Get the furthest instruction end
    let mut end = entry;
    for &address in instructions {
        let Some(offset) = address.checked_sub(entry) else {
            continue; // Skip addresses below the entry
        };
        if let DecodeOutcome::Ok(insn) = buffer.decode_at(decoder, data, offset as usize) {
            end = end.max(address + insn.length() as u32);
        }
    }
    if end == entry {
        return None;
    }

    // Get the original bytes
    let mut masked = data.get(..(end - entry) as usize)?.to_vec();

    for &address in instructions {
        let Some(offset) = address.checked_sub(entry) else {
            continue; // Skip addresses below the entry
        };
        let offset = offset as usize;
        let DecodeOutcome::Ok(insn) = buffer.decode_at(decoder, data, offset) else {
            continue;
        };
        let next = address.wrapping_add(insn.length() as u32);

        for field in insn.encoded_fields().into_iter().flatten() {
            let target = if field.relative_to_next_insn {
                next.wrapping_add(field.value as u32)
            } else {
                field.value as u32
            };

            // Branches that stay inside this function survive relocation.
            let inside_function = field.relative_to_next_insn && (entry..end).contains(&target);

            if !inside_function && image_range.contains(&target) {
                let start = offset + usize::from(field.offset);
                masked[start..start + usize::from(field.size)].fill(0);
            }
        }
    }

    Some(xxh3_128(&masked))
}
