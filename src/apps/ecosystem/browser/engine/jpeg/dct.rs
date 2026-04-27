// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

/// Standard JPEG zigzag scan order for an 8×8 block.
/// Maps zigzag position → row-major position.
const ZIGZAG_ORDER: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Dequantize and reorder zigzag coefficients into an 8×8 row-major block.
/// `coeffs` are in zigzag order, `quant_table` has 64 values also in zigzag order.
pub(super) fn dequantize_and_dezigzag(coeffs: &[i32; 64], quant_table: &[u16; 64]) -> [i32; 64] {
    let mut block = [0i32; 64];
    for i in 0..64 {
        block[ZIGZAG_ORDER[i]] = coeffs[i] * (quant_table[i] as i32);
    }
    block
}

/// Integer 8×8 IDCT using the AAN (Arai, Agui, Nakajima) algorithm.
/// Uses 12-bit fixed-point arithmetic — no floating point.
///
/// Input: dequantized 8×8 block in row-major order.
/// Output: pixel values in [0, 255] (level-shifted by +128).
pub(super) fn idct_8x8(block: &mut [i32; 64]) {
    // Fixed-point scale factors (scaled by 2^12 = 4096)
    // These are the cosine values for the AAN algorithm:
    // c[k] = cos(k * pi / 16) * sqrt(2), except c[0] = 1
    // Encoded as fixed-point with 12 fractional bits.
    const W1: i32 = 2841; // cos(1*pi/16) * 2048 * sqrt(2) ≈ 2841
    const W2: i32 = 2676; // cos(2*pi/16) * 2048 * sqrt(2) ≈ 2676
    const W3: i32 = 2408; // cos(3*pi/16) * 2048 * sqrt(2) ≈ 2408
    const W5: i32 = 1609; // cos(5*pi/16) * 2048 * sqrt(2) ≈ 1609
    const W6: i32 = 1108; // cos(6*pi/16) * 2048 * sqrt(2) ≈ 1108
    const W7: i32 = 565; // cos(7*pi/16) * 2048 * sqrt(2) ≈ 565

    // Row IDCT — process each row of 8
    for row in 0..8 {
        let base = row * 8;
        idct_row(&mut block[base..base + 8], W1, W2, W3, W5, W6, W7);
    }

    // Column IDCT — process each column of 8
    for col in 0..8 {
        let mut tmp = [0i32; 8];
        for r in 0..8 {
            tmp[r] = block[r * 8 + col];
        }
        idct_col(&mut tmp, W1, W2, W3, W5, W6, W7);
        for r in 0..8 {
            // Level shift (+128) and clamp to [0, 255]
            let val = (tmp[r] >> 14) + 128;
            block[r * 8 + col] = clamp_u8(val) as i32;
        }
    }
}

/// 1D IDCT on a row of 8 values (in-place).
/// Uses Chen-Wang-Fralick style butterfly decomposition.
#[inline]
fn idct_row(row: &mut [i32], w1: i32, w2: i32, w3: i32, w5: i32, w6: i32, w7: i32) {
    // Short-circuit: if all AC coefficients are zero, just scale DC
    if row[1] == 0
        && row[2] == 0
        && row[3] == 0
        && row[4] == 0
        && row[5] == 0
        && row[6] == 0
        && row[7] == 0
    {
        let dc = row[0] << 3;
        for v in row.iter_mut() {
            *v = dc;
        }
        return;
    }

    // Stage 1: dequant prescale
    let mut x0 = (row[0] << 11) + 128; // +128 for rounding
    let mut x1 = row[4] << 11;
    let x2 = row[6];
    let x3 = row[2];
    let mut x4 = row[1];
    let mut x5 = row[7];
    let mut x6 = row[5];
    let x7 = row[3];

    // Stage 2: even part
    let mut x8 = w7 * (x4 + x5);
    x4 = x8 + (w1 - w7) * x4;
    x5 = x8 - (w1 + w7) * x5;
    x8 = w3 * (x6 + x7);
    x6 = x8 - (w3 - w5) * x6;
    let x7 = x8 - (w3 + w5) * x7;

    // Stage 3
    x8 = x0 + x1;
    x0 -= x1;
    x1 = w6 * (x3 + x2);
    let x2 = x1 - (w2 + w6) * x2;
    let x3 = x1 + (w2 - w6) * x3;
    x1 = x4 + x6;
    x4 -= x6;
    let x6 = x5 + x7;
    x5 -= x7;

    // Stage 4
    let x7 = x8 + x3;
    x8 -= x3;
    let x3 = x0 + x2;
    x0 -= x2;
    let x2 = (181 * (x4 + x5) + 128) >> 8; // sqrt(2) * 128 ≈ 181
    x4 = (181 * (x4 - x5) + 128) >> 8;

    // Output (row is scaled by 2^8)
    row[0] = (x7 + x1) >> 8;
    row[1] = (x3 + x2) >> 8;
    row[2] = (x0 + x4) >> 8;
    row[3] = (x8 + x6) >> 8;
    row[4] = (x8 - x6) >> 8;
    row[5] = (x0 - x4) >> 8;
    row[6] = (x3 - x2) >> 8;
    row[7] = (x7 - x1) >> 8;
}

/// 1D IDCT on a column of 8 values (in-place).
/// Same butterfly as row but without the row-prescale.
#[inline]
fn idct_col(col: &mut [i32; 8], w1: i32, w2: i32, w3: i32, w5: i32, w6: i32, w7: i32) {
    // Short-circuit: if all AC coefficients are zero
    if col[1] == 0
        && col[2] == 0
        && col[3] == 0
        && col[4] == 0
        && col[5] == 0
        && col[6] == 0
        && col[7] == 0
    {
        let dc = (col[0] + 32) >> 6;
        for v in col.iter_mut() {
            *v = dc;
        }
        return;
    }

    let mut x0 = (col[0] << 8) + 8192; // +8192 for rounding in final >> 14
    let mut x1 = col[4] << 8;
    let x2 = col[6];
    let x3 = col[2];
    let mut x4 = col[1];
    let mut x5 = col[7];
    let mut x6 = col[5];
    let x7 = col[3];

    let mut x8 = w7 * (x4 + x5) + 4;
    x4 = (x8 + (w1 - w7) * x4) >> 3;
    x5 = (x8 - (w1 + w7) * x5) >> 3;
    x8 = w3 * (x6 + x7) + 4;
    x6 = (x8 - (w3 - w5) * x6) >> 3;
    let x7 = (x8 - (w3 + w5) * x7) >> 3;

    x8 = x0 + x1;
    x0 -= x1;
    x1 = w6 * (x3 + x2) + 4;
    let x2 = (x1 - (w2 + w6) * x2) >> 3;
    let x3 = (x1 + (w2 - w6) * x3) >> 3;
    x1 = x4 + x6;
    x4 -= x6;
    let x6 = x5 + x7;
    x5 -= x7;

    let x7 = x8 + x3;
    x8 -= x3;
    let x3 = x0 + x2;
    x0 -= x2;
    let x2 = (181 * (x4 + x5) + 128) >> 8;
    x4 = (181 * (x4 - x5) + 128) >> 8;

    col[0] = x7 + x1;
    col[1] = x3 + x2;
    col[2] = x0 + x4;
    col[3] = x8 + x6;
    col[4] = x8 - x6;
    col[5] = x0 - x4;
    col[6] = x3 - x2;
    col[7] = x7 - x1;
}

/// Clamp a value to the [0, 255] range.
#[inline(always)]
fn clamp_u8(val: i32) -> u8 {
    if val < 0 {
        0
    } else if val > 255 {
        255
    } else {
        val as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zigzag_order_valid() {
        // Each position 0-63 must appear exactly once
        let mut seen = [false; 64];
        for &idx in &ZIGZAG_ORDER {
            assert!(idx < 64);
            assert!(!seen[idx], "duplicate zigzag index {}", idx);
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn test_dequantize_dc_only() {
        // Only DC (position 0), quant=10 → output at ZIGZAG[0]=0 should be 100
        let mut coeffs = [0i32; 64];
        coeffs[0] = 10;
        let mut quant = [1u16; 64];
        quant[0] = 10;
        let block = dequantize_and_dezigzag(&coeffs, &quant);
        assert_eq!(block[0], 100); // 10 * 10
                                   // All others should be 0 (coeff=0)
        for i in 1..64 {
            assert_eq!(block[i], 0);
        }
    }

    #[test]
    fn test_idct_dc_only() {
        // A pure DC block: all 64 pixels should be the same value after IDCT
        let mut block = [0i32; 64];
        block[0] = 800; // arbitrary DC
        idct_8x8(&mut block);
        // All pixels should be close to 128 + (800 * scale)
        // With DC only, the IDCT should produce uniform output
        let first = block[0];
        for i in 1..64 {
            assert!(
                (block[i] - first).abs() <= 1,
                "pixel {} differs: {} vs {}",
                i,
                block[i],
                first
            );
        }
        // Value should be in [0, 255]
        assert!(first >= 0 && first <= 255);
    }

    #[test]
    fn test_idct_all_zero() {
        // All-zero input → all pixels should be 128 (level shift)
        let mut block = [0i32; 64];
        idct_8x8(&mut block);
        for i in 0..64 {
            assert_eq!(block[i], 128, "pixel {} should be 128, got {}", i, block[i]);
        }
    }

    #[test]
    fn test_clamp_boundaries() {
        assert_eq!(clamp_u8(-100), 0);
        assert_eq!(clamp_u8(0), 0);
        assert_eq!(clamp_u8(128), 128);
        assert_eq!(clamp_u8(255), 255);
        assert_eq!(clamp_u8(500), 255);
    }
}
