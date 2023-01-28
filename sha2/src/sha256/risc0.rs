extern crate alloc;

use alloc::vec::Vec;

const DIGEST_BYTES: usize = 32;
const DIGEST_WORDS: usize = DIGEST_BYTES / 4;
const BLOCK_BYTES: usize = DIGEST_BYTES * 2;
const BLOCK_WORDS: usize = DIGEST_WORDS * 2;

unsafe extern "C" {
    fn sys_sha_buffer(
        out_state: *mut [u32; DIGEST_WORDS],
        in_state: *const [u32; DIGEST_WORDS],
        buf: *const u8,
        count: u32,
    );
}

#[inline(always)]
fn compress_words(state: &mut [u32; DIGEST_WORDS], blocks: &[[u32; BLOCK_WORDS]]) {
    // SAFETY: `blocks` is a u32-aligned buffer of `blocks.len()` blocks,
    // matching r0vm's `sys_sha_buffer` ABI.
    unsafe {
        sys_sha_buffer(
            state,
            state,
            blocks.as_ptr() as *const u8,
            blocks.len() as u32,
        );
    }
}

// When the blocks are unaligned they must be copied in order to align them on
// a u32 word boundary before they can be passed to sys_sha_buffer.
fn read_unaligned_blocks(blocks: &[[u8; BLOCK_BYTES]]) -> Vec<[u32; BLOCK_WORDS]> {
    blocks
        .iter()
        // SAFETY: `[u8; BLOCK_BYTES]` and `[u32; BLOCK_WORDS]` have identical size.
        .map(|block| unsafe { (block.as_ptr() as *const [u32; BLOCK_WORDS]).read_unaligned() })
        .collect()
}

/// SHA-256 compress via the RISC Zero SHA-256 accelerator circuit.
#[inline]
pub fn compress(state: &mut [u32; DIGEST_WORDS], blocks: &[[u8; BLOCK_BYTES]]) {
    // r0vm expects the state in big-endian memory layout; flip before and after.
    for word in state.iter_mut() {
        *word = word.to_be();
    }

    // SAFETY: reinterpreting `[u8; BLOCK_BYTES]` as `[u32; BLOCK_WORDS]` preserves
    // size; the empty prefix/suffix guard ensures the slice was u32-aligned.
    match unsafe { blocks.align_to::<[u32; BLOCK_WORDS]>() } {
        (&[], aligned_blocks, &[]) => compress_words(state, aligned_blocks),
        _ => compress_words(state, &read_unaligned_blocks(blocks)),
    };

    for word in state.iter_mut() {
        *word = word.to_be();
    }
}
