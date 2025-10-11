//! Constant-time utility helpers suitable for crypto primitives.
//! - ct_eq: constant-time equality for byte slices
//! - ct_select_u8: constant-time select between two u8 values
//! - ct_conditional_move: constant-time conditional move for buffers

/// Constant-time equality: returns true iff a == b without early exits.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time compare for fixed-size arrays (convenience)
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time select: if cond==true return a else b (no branching on secret).
#[inline(always)]
pub fn ct_select_u8(cond: bool, a: u8, b: u8) -> u8 {
    let mask = (-(cond as i8)) as u8; // 0xFF or 0x00
    (mask & a) | (!mask & b)
}

/// Overwrite dst with src in constant-time conditional manner:
pub fn ct_conditional_move(dst: &mut [u8], src: &[u8], cond: bool) {
    if dst.len() != src.len() {
        return;
    }
    let mask = (-(cond as i8)) as u8;
    for i in 0..dst.len() {
        dst[i] = (mask & src[i]) | (!mask & dst[i]);
    }
}
