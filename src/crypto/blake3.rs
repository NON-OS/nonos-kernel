//! BLAKE3 (portable, single-threaded, no_std-friendly)

#![allow(clippy::many_single_char_names)]
#![allow(clippy::identity_op)]

use core::convert::TryInto;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const CHUNK_LEN: usize = 1024;
const BLOCK_LEN: usize = 64;
const OUT_LEN: usize = 32;
const ROUNDS: usize = 7;

// Flags
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32   = 1 << 1;
// const PARENT: u32      = 1 << 2; // used in parent node compress
// const ROOT: u32        = 1 << 3; // used at finalization if needed
// const KEYED_HASH: u32  = 1 << 4;
// const DERIVE_KEY: u32  = 1 << 5;
// const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// One-shot BLAKE3 (32-byte digest) for the default hash mode.
pub fn blake3_hash(input: &[u8]) -> [u8; OUT_LEN] {
    // Process input into chaining values (CVs) over 1KiB chunks
    let mut cvs = smallvec_cvs_capacity((input.len() + CHUNK_LEN - 1) / CHUNK_LEN);
    let mut offset = 0usize;
    let mut chunk_counter: u64 = 0;

    while offset < input.len() {
        let take = core::cmp::min(CHUNK_LEN, input.len() - offset);
        let chunk = &input[offset..offset + take];
        let cv = compress_chunk(chunk, chunk_counter);
        cvs_push(&mut cvs, cv);
        chunk_counter = chunk_counter.wrapping_add(1);
        offset += take;
    }

    // If no data, hash empty chunk
    if cvs_len(&cvs) == 0 {
        let cv = compress_chunk(&[], 0);
        cvs_push(&mut cvs, cv);
    }

    // Reduce CVs up the tree
    let mut n = cvs_len(&cvs);
    while n > 1 {
        let mut out_len = n / 2 + (n % 2);
        let mut i = 0usize;
        let mut j = 0usize;
        while i + 1 < n {
            let left = cvs_get(&cvs, i);
            let right = cvs_get(&cvs, i + 1);
            let parent = parent_compress(left, right);
            cvs_set(&mut cvs, j, parent);
            i += 2;
            j += 1;
        }
        if i < n {
            // odd element carried up
            let carry = cvs_get(&cvs, i);
            cvs_set(&mut cvs, j, carry);
            j += 1;
        }
        n = out_len;
        cvs_truncate(&mut cvs, n);
    }

    // Final output from the lone CV using the BLAKE3 XOF-style output function
    let cv = cvs_get(&cvs, 0);
    // We produce 32 bytes (one block of the output function)
    output_from_cv(cv)
}

// ---- Internal helpers ----

#[inline]
fn g(m: &[u32; 16], v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: usize, y: usize) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[x]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);

    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);

    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[y]);
    v[d] = (v[d] ^ v[a]).rotate_right(8);

    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline]
fn round(m: &[u32; 16], v: &mut [u32; 16]) {
    // Column rounds
    g(m, v, 0, 4, 8, 12, 0, 1);
    g(m, v, 1, 5, 9, 13, 2, 3);
    g(m, v, 2, 6, 10, 14, 4, 5);
    g(m, v, 3, 7, 11, 15, 6, 7);
    // Diagonal rounds
    g(m, v, 0, 5, 10, 15, 8, 9);
    g(m, v, 1, 6, 11, 12, 10, 11);
    g(m, v, 2, 7, 8, 13, 12, 13);
    g(m, v, 3, 4, 9, 14, 14, 15);
}

#[inline]
fn compress(
    chaining_value: [u32; 8],
    block_words: &[u32; 16],
    block_len: u32,
    counter_low: u32,
    counter_high: u32,
    flags: u32,
) -> [u32; 16] {
    // state v
    let mut v = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low, counter_high, block_len, flags,
    ];
    // rounds
    for _ in 0..ROUNDS {
        round(block_words, &mut v);
    }

    // output = (v[0..8] ^ v[8..16]) concatenated (chaining value words only per BLAKE3 spec)
    let mut out = [0u32; 16];
    for i in 0..8 {
        out[i] = v[i] ^ v[i + 8];
    }
    // The upper 8 words are "output block" words as well (v[8..16] ^ cv?), but CV derivation uses only first 8 words
    out[8..16].copy_from_slice(&v[8..16]);
    out
}

#[inline]
fn words_from_block(block: &[u8]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for i in 0..16 {
        let j = i * 4;
        w[i] = u32::from_le_bytes([
            block.get(j).copied().unwrap_or(0),
            block.get(j + 1).copied().unwrap_or(0),
            block.get(j + 2).copied().unwrap_or(0),
            block.get(j + 3).copied().unwrap_or(0),
        ]);
    }
    w
}

// Process a 1KiB chunk, returning the 8-word chaining value.
fn compress_chunk(chunk: &[u8], chunk_counter: u64) -> [u32; 8] {
    let mut cv = IV; // initial CV for default hash
    let mut offset = 0usize;
    let mut block_index = 0u32;
    let total = chunk.len();

    while offset < total {
        let take = core::cmp::min(BLOCK_LEN, total - offset);
        let block = &chunk[offset..offset + take];
        let mut block_buf = [0u8; BLOCK_LEN];
        block_buf[..take].copy_from_slice(block);

        let block_words = words_from_block(&block_buf);
        let is_start = block_index == 0;
        let is_end = offset + take == total;

        let flags = (if is_start { CHUNK_START } else { 0 })
            | (if is_end { CHUNK_END } else { 0 });

        let ctr_lo = (chunk_counter & 0xFFFF_FFFF) as u32;
        let ctr_hi = (chunk_counter >> 32) as u32;

        let out = compress(cv, &block_words, take as u32, ctr_lo, ctr_hi, flags);
        // derive next CV from first 8 words XOR with previous cv per spec:
        // In BLAKE3, chaining value for next block is the first 8 words of output (already XOR'd form).
        let mut next_cv = [0u32; 8];
        next_cv.copy_from_slice(&out[0..8]);
        cv = next_cv;

        offset += take;
        block_index = block_index.wrapping_add(1);
    }

    cv
}

// Parent node compress: combine two child CVs into a parent CV
fn parent_compress(left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
    // Build a 64-byte block from two CVs
    let mut block = [0u8; BLOCK_LEN];
    for (i, &w) in left.iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    for (i, &w) in right.iter().enumerate() {
        let j = 32 + i * 4;
        block[j..j + 4].copy_from_slice(&w.to_le_bytes());
    }
    let block_words = words_from_block(&block);

    // Flags: parent node (set PARENT=1<<2), but we only set it in the flags position.
    // Even if the flag isn't used downstream here, we mirror spec semantics to keep compatibility.
    let flags_parent = 1 << 2;

    let out = compress(IV, &block_words, BLOCK_LEN as u32, 0, 0, flags_parent);
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[0..8]);
    cv
}

// Final output function: derive 32 bytes from the final CV
fn output_from_cv(cv: [u32; 8]) -> [u8; 32] {
    // The output function uses counter as a block counter (XOF). For a 32B digest, 1 block is enough.
    let mut block = [0u8; BLOCK_LEN];
    // Form a block from the CV (first 32 bytes), rest zero
    for (i, &w) in cv.iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    // Compress with flags=ROOT (1<<3), counter=0, block_len=BLOCK_LEN
    let block_words = words_from_block(&block);
    let flags_root = 1 << 3;
    let out = compress(IV, &block_words, BLOCK_LEN as u32, 0, 0, flags_root);

    // The first 32 bytes of out (little-endian words) form the digest
    let mut digest = [0u8; 32];
    for i in 0..8 {
        digest[i * 4..i * 4 + 4].copy_from_slice(&out[i].to_le_bytes());
    }
    digest
}

// --- Minimal smallvec for fixed small number of CVs without heap deps beyond alloc ---
#[derive(Clone)]
struct CvVec {
    inner: alloc::vec::Vec<[u32; 8]>,
}
#[inline]
fn smallvec_cvs_capacity(cap: usize) -> CvVec {
    CvVec { inner: alloc::vec::Vec::with_capacity(core::cmp::max(1, cap)) }
}
#[inline] fn cvs_push(v: &mut CvVec, cv: [u32; 8]) { v.inner.push(cv); }
#[inline] fn cvs_len(v: &CvVec) -> usize { v.inner.len() }
#[inline] fn cvs_get(v: &CvVec, idx: usize) -> [u32; 8] { v.inner[idx] }
#[inline] fn cvs_set(v: &mut CvVec, idx: usize, cv: [u32; 8]) { v.inner[idx] = cv; }
#[inline] fn cvs_truncate(v: &mut CvVec, len: usize) { v.inner.truncate(len) }

// alloc is used
extern crate alloc;
