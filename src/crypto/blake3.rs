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
const PARENT: u32      = 1 << 2;
const ROOT: u32        = 1 << 3;
// const KEYED_HASH: u32  = 1 << 4;
// const DERIVE_KEY: u32  = 1 << 5;
// const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// Per-round message word permutation base (official BLAKE3 MSG_PERMUTATION).
/// The schedule for round r is this permutation applied r times to [0..15].
const MSG_PERMUTATION: [usize; 16] = [
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
];

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
    // We produce 32 bytes (output block 0)
    output_block_from_cv(cv, 0)
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
fn apply_permutation(times: usize, idx: &mut [usize; 16]) {
    // Apply MSG_PERMUTATION 'times' times to idx mapping
    let mut tmp = [0usize; 16];
    for _ in 0..times {
        for i in 0..16 {
            tmp[i] = idx[MSG_PERMUTATION[i]];
        }
        *idx = tmp;
    }
}

#[inline]
fn round(m: &[u32; 16], v: &mut [u32; 16], r: usize) {
    // Compute the schedule for round r by applying the base permutation r times.
    let mut s = [0usize; 16];
    for i in 0..16 { s[i] = i; }
    if r != 0 {
        apply_permutation(r, &mut s);
    }

    // Column rounds
    g(m, v, 0, 4,  8, 12, s[0],  s[1]);
    g(m, v, 1, 5,  9, 13, s[2],  s[3]);
    g(m, v, 2, 6, 10, 14, s[4],  s[5]);
    g(m, v, 3, 7, 11, 15, s[6],  s[7]);
    // Diagonal rounds
    g(m, v, 0, 5, 10, 15, s[8],  s[9]);
    g(m, v, 1, 6, 11, 12, s[10], s[11]);
    g(m, v, 2, 7,  8, 13, s[12], s[13]);
    g(m, v, 3, 4,  9, 14, s[14], s[15]);
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
    // rounds with per-round schedule
    for r in 0..ROUNDS {
        round(block_words, &mut v, r);
    }

    // output = v[0..8] ^ v[8..16] in first 8 words; keep the upper 8 words for XOF expansion 
    let mut out = [0u32; 16];
    for i in 0..8 {
        out[i] = v[i] ^ v[i + 8];
    }
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
        // chaining value for next block = first 8 words of output (already XOR'd)
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

    let out = compress(IV, &block_words, BLOCK_LEN as u32, 0, 0, PARENT);
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[0..8]);
    cv
}

// Correct XOF output: compress keyed by CV with zero message block, block_len=0,
// counter = output block index, flags = ROOT. For a 32-byte digest, use block 0.
fn output_block_from_cv(cv: [u32; 8], block_counter: u64) -> [u8; 32] {
    let zero_block_words = [0u32; 16];
    let out = compress(
        cv,
        &zero_block_words,
        0,
        (block_counter & 0xFFFF_FFFF) as u32,
        (block_counter >> 32) as u32,
        ROOT,
    );
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
