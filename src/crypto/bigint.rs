// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
// 
//! Arbitrary-Precision Unsigned Integer Arithmetic
//!
//! This module provides a `BigUint` type for cryptographic operations 
//! requiring integers larger than 64 bits. Designed for use in RSA, 
//! Diffie-Hellman, elliptic curve cryptography and other crypto primitives.
//!
//! # Features
//!
//! - Arbitrary precision unsigned integers
//! - Efficient multi-limb arithmetic (64-bit limbs)
//! - Knuth's Algorithm D for division
//! - Montgomery multiplication for fast modular exponentiation
//! - Extended Euclidean algorithm for modular inverse
//! - Miller-Rabin primality testing
//! - Secure memory zeroing on drop
//! - Constant-time comparison for crypto-sensitive operations
//!
//! # Security Considerations
//!
//! - Limbs are securely zeroed when `BigUint` is dropped
//! - `ct_eq()` provides constant-time comparison to prevent timing attacks
//! - Note: Standard arithmetic operations are NOT constant-time
//!
//! # Representation
//!
//! Integers are stored as a vector of 64-bit limbs in little-endian order
//! (least significant limb first). Leading zero limbs are stripped to
//! maintain canonical representation.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use core::cmp::Ordering;
use core::ops::{Add, Sub, Mul, Div, Rem, BitAnd, BitOr, BitXor, Shl, Shr};

use crate::crypto::constant_time::{secure_zero, compiler_fence};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Bits per limb
const LIMB_BITS: usize = 64;

/// Mask for a full limb
const LIMB_MAX: u64 = u64::MAX;

// ============================================================================
// BIGUINT STRUCTURE
// ============================================================================

/// Arbitrary precision unsigned integer
///
/// Represented as a vector of 64-bit limbs in little-endian order.
/// The value is `sum(limbs[i] * 2^(64*i))` for i = 0..limbs.len().
///
/// Invariant: `limbs` is never empty and contains no trailing zeros
/// (except for the value 0, which is represented as `[0]`).
#[derive(Clone, Eq)]
pub struct BigUint {
    /// Little-endian limbs (least significant first)
    limbs: Vec<u64>,
}

impl Drop for BigUint {
    fn drop(&mut self) {
        // Securely zero all limbs to prevent key material leakage
        for limb in &mut self.limbs {
            unsafe {
                core::ptr::write_volatile(limb, 0);
            }
        }
        compiler_fence();
    }
}

// ============================================================================
// CONSTRUCTORS
// ============================================================================

impl BigUint {
    /// Create a new BigUint with value 0
    #[inline]
    pub fn zero() -> Self {
        Self { limbs: vec![0] }
    }

    /// Create a new BigUint with value 1
    #[inline]
    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    /// Alias for zero() for compatibility
    #[inline]
    pub fn new() -> Self {
        Self::zero()
    }

    /// Create BigUint from a single u64
    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self { limbs: vec![val] }
    }

    /// Create BigUint from a u128
    pub fn from_u128(val: u128) -> Self {
        if val == 0 {
            Self::zero()
        } else {
            let lo = val as u64;
            let hi = (val >> 64) as u64;
            if hi == 0 {
                Self { limbs: vec![lo] }
            } else {
                Self { limbs: vec![lo, hi] }
            }
        }
    }

    /// Create BigUint from bytes in big-endian order
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice with most significant byte first
    ///
    /// # Returns
    ///
    /// A BigUint representing the value encoded in the bytes
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
            return Self::zero();
        }

        // Skip leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[start..];

        if bytes.is_empty() {
            return Self::zero();
        }

        // Calculate number of limbs needed
        let num_limbs = (bytes.len() + 7) / 8;
        let mut limbs = vec![0u64; num_limbs];

        // Process bytes from least significant to most significant
        for (i, &byte) in bytes.iter().rev().enumerate() {
            let limb_idx = i / 8;
            let byte_idx = i % 8;
            limbs[limb_idx] |= (byte as u64) << (byte_idx * 8);
        }

        Self::normalize(limbs)
    }

    /// Create BigUint from bytes in little-endian order
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice with least significant byte first
    ///
    /// # Returns
    ///
    /// A BigUint representing the value encoded in the bytes
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
            return Self::zero();
        }

        // Calculate number of limbs needed
        let num_limbs = (bytes.len() + 7) / 8;
        let mut limbs = vec![0u64; num_limbs];

        // Process bytes directly
        for (i, &byte) in bytes.iter().enumerate() {
            let limb_idx = i / 8;
            let byte_idx = i % 8;
            limbs[limb_idx] |= (byte as u64) << (byte_idx * 8);
        }

        Self::normalize(limbs)
    }

    /// Create BigUint from hexadecimal string
    ///
    /// Accepts uppercase or lowercase hex digits, with optional "0x" prefix.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

        if s.is_empty() {
            return Some(Self::zero());
        }

        // Validate hex string
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        // Pad to multiple of 16 chars (8 bytes = 1 limb worth)
        let padded_len = ((s.len() + 15) / 16) * 16;
        let padding = padded_len - s.len();

        let num_limbs = padded_len / 16;
        let mut limbs = vec![0u64; num_limbs];

        // Parse from most significant to least significant
        for (i, chunk) in s.as_bytes().chunks(16).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).ok()?;
            let limb_idx = num_limbs - 1 - i;

            // Handle first chunk which may need padding
            if i == 0 && padding > 0 {
                let val = u64::from_str_radix(chunk_str, 16).ok()?;
                limbs[limb_idx] = val;
            } else {
                let val = u64::from_str_radix(chunk_str, 16).ok()?;
                limbs[limb_idx] = val;
            }
        }

        Some(Self::normalize(limbs))
    }

    /// Normalize limbs by removing trailing zeros
    fn normalize(mut limbs: Vec<u64>) -> Self {
        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }
        if limbs.is_empty() {
            limbs.push(0);
        }
        Self { limbs }
    }
}

// ============================================================================
// CONVERSION TO BYTES/HEX
// ============================================================================

impl BigUint {
    /// Convert to bytes in big-endian order
    ///
    /// Returns the minimal representation (no leading zero bytes,
    /// except for the value 0 which returns `[0]`).
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);

        // Process limbs from most significant to least significant
        let mut started = false;
        for &limb in self.limbs.iter().rev() {
            let limb_bytes = limb.to_be_bytes();
            if !started {
                // Skip leading zeros in most significant limb
                for &b in &limb_bytes {
                    if b != 0 || started {
                        bytes.push(b);
                        started = true;
                    }
                }
            } else {
                bytes.extend_from_slice(&limb_bytes);
            }
        }

        if bytes.is_empty() {
            vec![0]
        } else {
            bytes
        }
    }

    /// Convert to bytes in big-endian order with fixed size
    ///
    /// Pads with leading zeros or truncates to fit the specified size.
    /// Returns None if the value doesn't fit in the specified size.
    pub fn to_bytes_be_padded(&self, size: usize) -> Option<Vec<u8>> {
        let bytes = self.to_bytes_be();
        if bytes.len() > size {
            return None;
        }

        let mut result = vec![0u8; size];
        let start = size - bytes.len();
        result[start..].copy_from_slice(&bytes);
        Some(result)
    }

    /// Convert to bytes in little-endian order
    pub fn to_bytes_le(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);

        for &limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }

        // Remove trailing zeros
        while bytes.len() > 1 && bytes.last() == Some(&0) {
            bytes.pop();
        }

        bytes
    }

    /// Convert to hexadecimal string (lowercase, no prefix)
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return String::from("0");
        }

        let bytes = self.to_bytes_be();
        let mut hex = String::with_capacity(bytes.len() * 2);

        for (i, &b) in bytes.iter().enumerate() {
            if i == 0 {
                // Don't pad first byte
                if b < 16 {
                    hex.push(char::from_digit(b as u32, 16).unwrap());
                } else {
                    hex.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                    hex.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
                }
            } else {
                hex.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                hex.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
            }
        }

        hex
    }

    /// Convert to u64, returning None if the value doesn't fit
    pub fn to_u64(&self) -> Option<u64> {
        if self.limbs.len() == 1 {
            Some(self.limbs[0])
        } else if self.limbs.len() == 0 {
            Some(0)
        } else {
            None
        }
    }

    /// Convert to u128, returning None if the value doesn't fit
    pub fn to_u128(&self) -> Option<u128> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0] as u128),
            2 => Some((self.limbs[1] as u128) << 64 | (self.limbs[0] as u128)),
            _ => None,
        }
    }
}

// ============================================================================
// PREDICATES
// ============================================================================

impl BigUint {
    /// Check if the value is zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 0
    }

    /// Check if the value is one
    #[inline]
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    /// Check if the value is odd
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    /// Check if the value is even
    #[inline]
    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    /// Get the number of significant bits
    ///
    /// Returns 0 for zero, otherwise the position of the highest set bit + 1.
    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let top_limb = self.limbs[self.limbs.len() - 1];
        let top_bits = LIMB_BITS - top_limb.leading_zeros() as usize;
        (self.limbs.len() - 1) * LIMB_BITS + top_bits
    }

    /// Get the number of limbs
    #[inline]
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    /// Get a reference to the limbs
    #[inline]
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }
}

// ============================================================================
// BIT OPERATIONS
// ============================================================================

impl BigUint {
    /// Get the i-th bit (0 = least significant)
    #[inline]
    pub fn bit(&self, i: usize) -> bool {
        let limb_idx = i / LIMB_BITS;
        let bit_idx = i % LIMB_BITS;

        if limb_idx >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1 == 1
        }
    }

    /// Set the i-th bit
    pub fn set_bit(&mut self, i: usize, value: bool) {
        let limb_idx = i / LIMB_BITS;
        let bit_idx = i % LIMB_BITS;

        // Extend if necessary
        while limb_idx >= self.limbs.len() {
            self.limbs.push(0);
        }

        if value {
            self.limbs[limb_idx] |= 1u64 << bit_idx;
        } else {
            self.limbs[limb_idx] &= !(1u64 << bit_idx);
            // Re-normalize
            while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
                self.limbs.pop();
            }
        }
    }

    /// Count trailing zeros
    pub fn trailing_zeros(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let mut count = 0;
        for &limb in &self.limbs {
            if limb == 0 {
                count += LIMB_BITS;
            } else {
                count += limb.trailing_zeros() as usize;
                break;
            }
        }
        count
    }

    /// Count leading zeros (relative to current size)
    pub fn leading_zeros(&self) -> usize {
        if self.is_zero() {
            return LIMB_BITS;
        }

        self.limbs.last().unwrap().leading_zeros() as usize
    }

    /// Left shift by n bits
    pub fn shl_bits(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }

        let limb_shift = n / LIMB_BITS;
        let bit_shift = n % LIMB_BITS;

        let new_len = self.limbs.len() + limb_shift + 1;
        let mut result = vec![0u64; new_len];

        if bit_shift == 0 {
            for i in 0..self.limbs.len() {
                result[i + limb_shift] = self.limbs[i];
            }
        } else {
            let mut carry = 0u64;
            for i in 0..self.limbs.len() {
                let limb = self.limbs[i];
                result[i + limb_shift] = (limb << bit_shift) | carry;
                carry = limb >> (LIMB_BITS - bit_shift);
            }
            if carry != 0 {
                result[self.limbs.len() + limb_shift] = carry;
            }
        }

        Self::normalize(result)
    }

    /// Right shift by n bits
    pub fn shr_bits(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }

        let limb_shift = n / LIMB_BITS;
        let bit_shift = n % LIMB_BITS;

        if limb_shift >= self.limbs.len() {
            return Self::zero();
        }

        let new_len = self.limbs.len() - limb_shift;
        let mut result = vec![0u64; new_len];

        if bit_shift == 0 {
            for i in 0..new_len {
                result[i] = self.limbs[i + limb_shift];
            }
        } else {
            for i in 0..new_len {
                let limb = self.limbs[i + limb_shift];
                result[i] = limb >> bit_shift;
                if i + limb_shift + 1 < self.limbs.len() {
                    result[i] |= self.limbs[i + limb_shift + 1] << (LIMB_BITS - bit_shift);
                }
            }
        }

        Self::normalize(result)
    }

    /// Left shift by one bit (optimized)
    pub fn shl_1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }

        let mut result = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u64;

        for &limb in &self.limbs {
            let new_carry = limb >> 63;
            result.push((limb << 1) | carry);
            carry = new_carry;
        }

        if carry != 0 {
            result.push(carry);
        }

        Self { limbs: result }
    }

    /// Right shift by one bit (optimized)
    pub fn shr_1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }

        let mut result = vec![0u64; self.limbs.len()];
        let mut carry = 0u64;

        for i in (0..self.limbs.len()).rev() {
            let new_carry = (self.limbs[i] & 1) << 63;
            result[i] = (self.limbs[i] >> 1) | carry;
            carry = new_carry;
        }

        Self::normalize(result)
    }

    // Legacy aliases
    pub fn shl(&self, n: usize) -> Self { self.shl_bits(n) }
    pub fn shr(&self, n: usize) -> Self { self.shr_bits(n) }
}

// ============================================================================
// COMPARISON
// ============================================================================

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        self.limbs == other.limbs
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by length first
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                // Same length: compare limbs from most significant
                for i in (0..self.limbs.len()).rev() {
                    match self.limbs[i].cmp(&other.limbs[i]) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }
}

impl BigUint {
    /// Constant-time equality comparison
    ///
    /// Returns true if self == other in constant time.
    /// This is essential for comparing secrets like keys or MACs.
    ///
    /// # Security
    ///
    /// This function executes in constant time regardless of the values being
    /// compared, preventing timing side-channel attacks.
    pub fn ct_eq(&self, other: &Self) -> bool {
        // Always iterate over max length to avoid timing leaks
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut diff = 0u64;

        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }

        // Also account for length difference in constant time
        // XOR the lengths - if different, this will be non-zero
        diff |= (self.limbs.len() ^ other.limbs.len()) as u64;

        // Convert to bool in constant time
        // If diff is 0, result is true; otherwise false
        diff == 0
    }
}

// ============================================================================
// ADDITION
// ============================================================================

impl Add<&BigUint> for &BigUint {
    type Output = BigUint;

    fn add(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;

        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);

            // Compute a + b + carry with u128 to handle overflow
            let sum = (a as u128) + (b as u128) + (carry as u128);
            result.push(sum as u64);
            carry = (sum >> 64) as u64;
        }

        if carry != 0 {
            result.push(carry);
        }

        BigUint { limbs: result }
    }
}

// Implement other Add variants
impl Add<BigUint> for BigUint {
    type Output = BigUint;
    fn add(self, other: BigUint) -> BigUint { &self + &other }
}

impl Add<&BigUint> for BigUint {
    type Output = BigUint;
    fn add(self, other: &BigUint) -> BigUint { &self + other }
}

impl Add<BigUint> for &BigUint {
    type Output = BigUint;
    fn add(self, other: BigUint) -> BigUint { self + &other }
}

impl BigUint {
    /// Add a u64 value
    pub fn add_u64(&self, val: u64) -> Self {
        if val == 0 {
            return self.clone();
        }

        let mut result = self.limbs.clone();
        let mut carry = val as u128;
        let mut i = 0;

        while carry != 0 {
            if i >= result.len() {
                result.push(0);
            }
            let sum = (result[i] as u128) + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
            i += 1;
        }

        BigUint { limbs: result }
    }
}

// ============================================================================
// SUBTRACTION
// ============================================================================

impl Sub<&BigUint> for &BigUint {
    type Output = BigUint;

    fn sub(self, other: &BigUint) -> BigUint {
        debug_assert!(self >= other, "Subtraction underflow");

        let mut result = self.limbs.clone();
        let mut borrow = 0i128;

        for i in 0..result.len() {
            let a = result[i] as i128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i128;
            let diff = a - b - borrow;

            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        debug_assert!(borrow == 0, "Subtraction underflow");
        BigUint::normalize(result)
    }
}

impl Sub<BigUint> for BigUint {
    type Output = BigUint;
    fn sub(self, other: BigUint) -> BigUint { &self - &other }
}

impl Sub<&BigUint> for BigUint {
    type Output = BigUint;
    fn sub(self, other: &BigUint) -> BigUint { &self - other }
}

impl Sub<BigUint> for &BigUint {
    type Output = BigUint;
    fn sub(self, other: BigUint) -> BigUint { self - &other }
}

impl BigUint {
    /// Subtract a u64 value, returns None on underflow
    pub fn sub_u64(&self, val: u64) -> Option<Self> {
        if self.limbs.len() == 1 && self.limbs[0] < val {
            return None;
        }

        let mut result = self.limbs.clone();
        let mut borrow = val as u128;
        let mut i = 0;

        while borrow != 0 && i < result.len() {
            if (result[i] as u128) >= borrow {
                result[i] -= borrow as u64;
                borrow = 0;
            } else {
                let diff = ((1u128 << 64) + (result[i] as u128)) - borrow;
                result[i] = diff as u64;
                borrow = 1;
            }
            i += 1;
        }

        if borrow != 0 {
            return None;
        }

        Some(BigUint::normalize(result))
    }

    /// Saturating subtraction: returns 0 if result would underflow
    pub fn saturating_sub(&self, other: &Self) -> Self {
        if self >= other {
            self - other
        } else {
            Self::zero()
        }
    }
}

// ============================================================================
// MULTIPLICATION
// ============================================================================

impl Mul<&BigUint> for &BigUint {
    type Output = BigUint;

    fn mul(self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }

        // Use schoolbook multiplication for now
        // For very large numbers, Karatsuba or FFT would be faster
        let result_len = self.limbs.len() + other.limbs.len();
        let mut result = vec![0u64; result_len];

        for i in 0..self.limbs.len() {
            let mut carry = 0u128;

            for j in 0..other.limbs.len() {
                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (result[i + j] as u128)
                    + carry;
                result[i + j] = product as u64;
                carry = product >> 64;
            }

            // Propagate final carry
            let mut k = i + other.limbs.len();
            while carry != 0 {
                let sum = (result[k] as u128) + carry;
                result[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        BigUint::normalize(result)
    }
}

impl Mul<BigUint> for BigUint {
    type Output = BigUint;
    fn mul(self, other: BigUint) -> BigUint { &self * &other }
}

impl Mul<&BigUint> for BigUint {
    type Output = BigUint;
    fn mul(self, other: &BigUint) -> BigUint { &self * other }
}

impl Mul<BigUint> for &BigUint {
    type Output = BigUint;
    fn mul(self, other: BigUint) -> BigUint { self * &other }
}

impl BigUint {
    /// Multiply by a u64 value
    pub fn mul_u64(&self, val: u64) -> Self {
        if val == 0 || self.is_zero() {
            return Self::zero();
        }
        if val == 1 {
            return self.clone();
        }

        let mut result = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u128;

        for &limb in &self.limbs {
            let product = (limb as u128) * (val as u128) + carry;
            result.push(product as u64);
            carry = product >> 64;
        }

        if carry != 0 {
            result.push(carry as u64);
        }

        BigUint { limbs: result }
    }

    /// Square the value (slightly more efficient than self * self)
    pub fn square(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        if self.is_one() {
            return Self::one();
        }

        // For now, use regular multiplication
        // TODO: Optimize with squaring algorithm
        self * self
    }
}

// ============================================================================
// DIVISION (Knuth's Algorithm D)
// ============================================================================

impl BigUint {
    /// Division with remainder using Knuth's Algorithm D
    ///
    /// Returns (quotient, remainder) such that self = quotient * divisor + remainder
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        // Handle trivial cases
        if self.is_zero() {
            return (Self::zero(), Self::zero());
        }

        match self.cmp(divisor) {
            Ordering::Less => return (Self::zero(), self.clone()),
            Ordering::Equal => return (Self::one(), Self::zero()),
            Ordering::Greater => {}
        }

        // Single-limb divisor: use simple algorithm
        if divisor.limbs.len() == 1 {
            return self.div_rem_u64(divisor.limbs[0]);
        }

        // Knuth's Algorithm D
        self.div_rem_knuth(divisor)
    }

    /// Division by a single u64
    fn div_rem_u64(&self, divisor: u64) -> (Self, Self) {
        if divisor == 0 {
            panic!("Division by zero");
        }

        let mut quotient = vec![0u64; self.limbs.len()];
        let mut remainder = 0u128;

        for i in (0..self.limbs.len()).rev() {
            let dividend = (remainder << 64) | (self.limbs[i] as u128);
            quotient[i] = (dividend / (divisor as u128)) as u64;
            remainder = dividend % (divisor as u128);
        }

        (
            BigUint::normalize(quotient),
            BigUint::from_u64(remainder as u64),
        )
    }

    /// Knuth's Algorithm D for multi-limb division
    fn div_rem_knuth(&self, divisor: &Self) -> (Self, Self) {
        let n = divisor.limbs.len();
        let m = self.limbs.len() - n;

        // D1: Normalize
        let shift = divisor.limbs[n - 1].leading_zeros();
        let mut u = self.shl_bits(shift as usize);
        let v = divisor.shl_bits(shift as usize);

        // Ensure u has m+n+1 limbs
        while u.limbs.len() <= m + n {
            u.limbs.push(0);
        }

        let mut q = vec![0u64; m + 1];

        // D2-D7: Main loop
        for j in (0..=m).rev() {
            // D3: Calculate q̂
            let u_hi = ((u.limbs[j + n] as u128) << 64) | (u.limbs[j + n - 1] as u128);
            let mut qhat = u_hi / (v.limbs[n - 1] as u128);
            let mut rhat = u_hi % (v.limbs[n - 1] as u128);

            // Adjust q̂
            while qhat >= (1u128 << 64) ||
                  (n >= 2 && qhat * (v.limbs[n - 2] as u128) > ((rhat << 64) | (u.limbs[j + n - 2] as u128))) {
                qhat -= 1;
                rhat += v.limbs[n - 1] as u128;
                if rhat >= (1u128 << 64) {
                    break;
                }
            }

            // D4: Multiply and subtract
            let mut borrow = 0i128;
            for i in 0..n {
                let product = (qhat as u128) * (v.limbs[i] as u128);
                let sub = (u.limbs[j + i] as i128) - (product as u64 as i128) - borrow;
                u.limbs[j + i] = sub as u64;
                borrow = (product >> 64) as i128 - (sub >> 64);
            }
            let sub = (u.limbs[j + n] as i128) - borrow;
            u.limbs[j + n] = sub as u64;

            // D5: Test remainder
            q[j] = qhat as u64;

            // D6: Add back if negative
            if sub < 0 {
                q[j] -= 1;
                let mut carry = 0u64;
                for i in 0..n {
                    let sum = (u.limbs[j + i] as u128) + (v.limbs[i] as u128) + (carry as u128);
                    u.limbs[j + i] = sum as u64;
                    carry = (sum >> 64) as u64;
                }
                u.limbs[j + n] = u.limbs[j + n].wrapping_add(carry);
            }
        }

        // D8: Unnormalize remainder
        u.limbs.truncate(n);
        let remainder = BigUint::normalize(u.limbs.clone()).shr_bits(shift as usize);

        (BigUint::normalize(q), remainder)
    }
}

impl Div<&BigUint> for &BigUint {
    type Output = BigUint;
    fn div(self, other: &BigUint) -> BigUint { self.div_rem(other).0 }
}

impl Div<BigUint> for BigUint {
    type Output = BigUint;
    fn div(self, other: BigUint) -> BigUint { &self / &other }
}

impl Div<&BigUint> for BigUint {
    type Output = BigUint;
    fn div(self, other: &BigUint) -> BigUint { &self / other }
}

impl Div<BigUint> for &BigUint {
    type Output = BigUint;
    fn div(self, other: BigUint) -> BigUint { self / &other }
}

impl Rem<&BigUint> for &BigUint {
    type Output = BigUint;
    fn rem(self, other: &BigUint) -> BigUint { self.div_rem(other).1 }
}

impl Rem<BigUint> for BigUint {
    type Output = BigUint;
    fn rem(self, other: BigUint) -> BigUint { &self % &other }
}

impl Rem<&BigUint> for BigUint {
    type Output = BigUint;
    fn rem(self, other: &BigUint) -> BigUint { &self % other }
}

impl Rem<BigUint> for &BigUint {
    type Output = BigUint;
    fn rem(self, other: BigUint) -> BigUint { self % &other }
}

// ============================================================================
// BITWISE OPERATIONS
// ============================================================================

impl BitAnd<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitand(self, other: &BigUint) -> BigUint {
        let len = core::cmp::min(self.limbs.len(), other.limbs.len());
        let limbs: Vec<u64> = (0..len)
            .map(|i| self.limbs[i] & other.limbs[i])
            .collect();
        BigUint::normalize(limbs)
    }
}

impl BitAnd<BigUint> for BigUint {
    type Output = BigUint;
    fn bitand(self, other: BigUint) -> BigUint { &self & &other }
}

impl BitOr<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitor(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let limbs: Vec<u64> = (0..max_len)
            .map(|i| {
                let a = self.limbs.get(i).copied().unwrap_or(0);
                let b = other.limbs.get(i).copied().unwrap_or(0);
                a | b
            })
            .collect();
        BigUint { limbs }
    }
}

impl BitOr<BigUint> for BigUint {
    type Output = BigUint;
    fn bitor(self, other: BigUint) -> BigUint { &self | &other }
}

impl BitOr<&BigUint> for BigUint {
    type Output = BigUint;
    fn bitor(self, other: &BigUint) -> BigUint { &self | other }
}

impl BitXor<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitxor(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let limbs: Vec<u64> = (0..max_len)
            .map(|i| {
                let a = self.limbs.get(i).copied().unwrap_or(0);
                let b = other.limbs.get(i).copied().unwrap_or(0);
                a ^ b
            })
            .collect();
        BigUint::normalize(limbs)
    }
}

impl BitXor<BigUint> for BigUint {
    type Output = BigUint;
    fn bitxor(self, other: BigUint) -> BigUint { &self ^ &other }
}

// Shift operators
impl Shl<usize> for &BigUint {
    type Output = BigUint;
    fn shl(self, n: usize) -> BigUint { self.shl_bits(n) }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;
    fn shl(self, n: usize) -> BigUint { (&self).shl_bits(n) }
}

impl Shr<usize> for &BigUint {
    type Output = BigUint;
    fn shr(self, n: usize) -> BigUint { self.shr_bits(n) }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;
    fn shr(self, n: usize) -> BigUint { (&self).shr_bits(n) }
}

// ============================================================================
// MODULAR ARITHMETIC
// ============================================================================

impl BigUint {
    /// Modular exponentiation: self^exp mod modulus
    ///
    /// Uses square-and-multiply algorithm. For large moduli,
    /// consider using Montgomery multiplication for better performance.
    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            panic!("Modulus cannot be zero");
        }
        if modulus.is_one() {
            return Self::zero();
        }
        if exp.is_zero() {
            return Self::one();
        }

        // Use Montgomery multiplication for odd moduli (more efficient)
        // Skip Montgomery when modulus is very close to a power of 2 (like 2^n - 1)
        // because R = 2^k mod m becomes very small, breaking Montgomery assumptions
        let n_limbs = modulus.limbs.len();
        let mod_bits = modulus.bits();
        let is_close_to_pow2 = mod_bits >= n_limbs * LIMB_BITS - 8; // Within 8 bits of 2^(n*64)
        if modulus.is_odd() && modulus.bits() >= 64 && !is_close_to_pow2 {
            return self.mod_pow_montgomery(exp, modulus);
        }

        // Standard square-and-multiply
        let mut result = Self::one();
        let mut base = self % modulus;
        let mut e = exp.clone();

        while !e.is_zero() {
            if e.is_odd() {
                result = (&result * &base) % modulus;
            }
            base = base.square() % modulus;
            e = e.shr_1();
        }

        result
    }

    /// Montgomery modular exponentiation for odd moduli
    fn mod_pow_montgomery(&self, exp: &Self, modulus: &Self) -> Self {
        debug_assert!(modulus.is_odd());

        let n = modulus.limbs.len();
        let r_bits = n * LIMB_BITS;

        // Compute R = 2^(n*64) mod modulus
        let r = Self::one().shl_bits(r_bits) % modulus;

        // Compute R^2 mod modulus
        let r2 = r.square() % modulus;

        // Compute modulus inverse: -modulus^(-1) mod 2^64
        let m_inv = Self::montgomery_inverse(modulus.limbs[0]);

        // Convert base to Montgomery form: aR mod modulus
        let mut base = self % modulus;
        base = Self::montgomery_reduce(&(&base * &r2), modulus, m_inv);

        // Result starts as R mod modulus (which is 1 in Montgomery form)
        let mut result = r.clone();

        let mut e = exp.clone();
        while !e.is_zero() {
            if e.is_odd() {
                // result = result * base * R^(-1) mod modulus
                result = Self::montgomery_reduce(&(&result * &base), modulus, m_inv);
            }
            // base = base^2 * R^(-1) mod modulus
            base = Self::montgomery_reduce(&base.square(), modulus, m_inv);
            e = e.shr_1();
        }

        // Convert back from Montgomery form
        Self::montgomery_reduce(&result, modulus, m_inv)
    }

    /// Compute -m^(-1) mod 2^64 using Newton's method
    fn montgomery_inverse(m0: u64) -> u64 {
        // m0 must be odd
        debug_assert!(m0 & 1 == 1);

        let mut y = 1u64;
        for _ in 0..6 {
            y = y.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(y)));
        }
        y.wrapping_neg()
    }

    /// Montgomery reduction: compute T * R^(-1) mod modulus
    fn montgomery_reduce(t: &Self, modulus: &Self, m_inv: u64) -> Self {
        let n = modulus.limbs.len();
        let mut a = t.limbs.clone();

        // Ensure a has enough limbs
        while a.len() < 2 * n {
            a.push(0);
        }

        for i in 0..n {
            let u = a[i].wrapping_mul(m_inv);

            let mut carry = 0u128;
            for j in 0..n {
                let sum = (a[i + j] as u128) + (u as u128) * (modulus.limbs[j] as u128) + carry;
                a[i + j] = sum as u64;
                carry = sum >> 64;
            }

            // Propagate carry
            let mut k = i + n;
            while carry != 0 && k < a.len() {
                let sum = (a[k] as u128) + carry;
                a[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
            if carry != 0 {
                a.push(carry as u64);
            }
        }

        // Shift right by n limbs (divide by R)
        let result_limbs: Vec<u64> = a[n..].to_vec();
        let mut result = BigUint::normalize(result_limbs);

        // Final subtraction if result >= modulus
        if &result >= modulus {
            result = &result - modulus;
        }

        result
    }

    /// Modular inverse using extended Euclidean algorithm
    ///
    /// Returns self^(-1) mod modulus, or None if gcd(self, modulus) != 1
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }

        // Extended Euclidean algorithm with signed coefficients
        let mut old_r = modulus.clone();
        let mut r = self % modulus;

        if r.is_zero() {
            return None;
        }

        let mut old_s = Self::zero();
        let mut s = Self::one();
        let mut old_s_neg = false;
        let mut s_neg = false;

        while !r.is_zero() {
            let (q, new_r) = old_r.div_rem(&r);

            old_r = r;
            r = new_r;

            // Update s: new_s = old_s - q * s
            let qs = &q * &s;

            let (new_s, new_s_neg) = if old_s_neg == s_neg {
                // Same sign
                if old_s >= qs {
                    (&old_s - &qs, old_s_neg)
                } else {
                    (&qs - &old_s, !old_s_neg)
                }
            } else {
                // Different signs: old_s + qs (effectively)
                (&old_s + &qs, old_s_neg)
            };

            old_s = s;
            old_s_neg = s_neg;
            s = new_s;
            s_neg = new_s_neg;
        }

        // Check gcd == 1
        if !old_r.is_one() {
            return None;
        }

        // Adjust sign
        let result = if old_s_neg {
            modulus - &(old_s % modulus)
        } else {
            old_s % modulus
        };

        Some(result)
    }

    /// Greatest Common Divisor using binary GCD algorithm
    pub fn gcd(&self, other: &Self) -> Self {
        if self.is_zero() {
            return other.clone();
        }
        if other.is_zero() {
            return self.clone();
        }

        let mut a = self.clone();
        let mut b = other.clone();

        // Find common factors of 2
        let a_tz = a.trailing_zeros();
        let b_tz = b.trailing_zeros();
        let shift = core::cmp::min(a_tz, b_tz);

        a = a.shr_bits(a_tz);
        b = b.shr_bits(b_tz);

        loop {
            // a is odd here
            if a > b {
                core::mem::swap(&mut a, &mut b);
            }

            b = &b - &a;

            if b.is_zero() {
                return a.shl_bits(shift);
            }

            b = b.shr_bits(b.trailing_zeros());
        }
    }

    /// Least Common Multiple
    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let g = self.gcd(other);
        (self / &g) * other
    }
}

// ============================================================================
// PRIMALITY TESTING
// ============================================================================

impl BigUint {
    /// Miller-Rabin primality test
    ///
    /// Returns true if self is probably prime, false if definitely composite.
    /// The probability of a false positive is at most 4^(-k).
    ///
    /// # Arguments
    ///
    /// * `k` - Number of rounds (40 recommended for cryptographic use)
    pub fn is_probably_prime(&self, k: usize) -> bool {
        // Handle small cases
        if self.limbs.len() == 1 {
            let n = self.limbs[0];
            if n < 2 {
                return false;
            }
            if n == 2 || n == 3 {
                return true;
            }
            if n % 2 == 0 {
                return false;
            }
            // Small primes check
            const SMALL_PRIMES: [u64; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
            for &p in &SMALL_PRIMES {
                if n == p {
                    return true;
                }
                if n % p == 0 {
                    return false;
                }
            }
        }

        if self.is_even() {
            return *self == Self::from_u64(2);
        }

        // Write n-1 as d * 2^r
        let n_minus_1 = self.sub_u64(1).unwrap();
        let r = n_minus_1.trailing_zeros();
        let d = n_minus_1.shr_bits(r);

        // Deterministic witnesses for numbers up to certain bounds
        let witnesses: &[u64] = if self.bits() <= 32 {
            &[2, 7, 61]
        } else if self.bits() <= 64 {
            &[2, 325, 9375, 28178, 450775, 9780504, 1795265022]
        } else {
            // For larger numbers, use random witnesses
            return self.miller_rabin_random(&d, r, k);
        };

        for &a in witnesses {
            let a_big = Self::from_u64(a);
            if a_big >= *self {
                continue;
            }
            if !self.miller_rabin_witness(&a_big, &d, r) {
                return false;
            }
        }

        true
    }

    /// Single Miller-Rabin witness test
    fn miller_rabin_witness(&self, a: &Self, d: &Self, r: usize) -> bool {
        let n_minus_1 = self.sub_u64(1).unwrap();

        let mut x = a.mod_pow(d, self);

        if x.is_one() || x == n_minus_1 {
            return true;
        }

        for _ in 0..r - 1 {
            x = x.square() % self;
            if x == n_minus_1 {
                return true;
            }
            if x.is_one() {
                return false;
            }
        }

        false
    }

    /// Miller-Rabin with random witnesses
    fn miller_rabin_random(&self, d: &Self, r: usize, k: usize) -> bool {
        let n_minus_1 = self.sub_u64(1).unwrap();
        let two = Self::from_u64(2);

        for _ in 0..k {
            // Generate random witness in [2, n-2]
            let a = Self::random_range(&two, &n_minus_1);
            if !self.miller_rabin_witness(&a, d, r) {
                return false;
            }
        }

        true
    }

    /// Generate a random BigUint in [min, max)
    ///
    /// Uses rejection sampling to avoid modulo bias, ensuring uniform distribution.
    pub fn random_range(min: &Self, max: &Self) -> Self {
        if min >= max {
            return min.clone();
        }

        let range = max - min;
        let range_bits = range.bits();
        let range_bytes = (range_bits + 7) / 8;

        // Rejection sampling loop to avoid modulo bias
        // Expected iterations: < 2 (since we mask to correct bit length)
        loop {
            // Gather enough random bytes
            let mut bytes = Vec::with_capacity(range_bytes);
            let mut remaining = range_bytes;

            while remaining > 0 {
                let rng_bytes = crate::crypto::rng::get_random_bytes();
                let take = core::cmp::min(remaining, rng_bytes.len());
                bytes.extend_from_slice(&rng_bytes[..take]);
                remaining = remaining.saturating_sub(take);
            }

            // Mask off excess bits in the top byte to get value in [0, 2^range_bits)
            let excess_bits = (range_bytes * 8) - range_bits;
            if excess_bits > 0 && !bytes.is_empty() {
                bytes[0] &= (1u8 << (8 - excess_bits)) - 1;
            }

            let random_val = Self::from_bytes_be(&bytes);

            // Rejection sampling: if random_val >= range, retry
            // This ensures uniform distribution without modulo bias
            if random_val < range {
                return min + &random_val;
            }
            // Retry with new random bytes
        }
    }

    /// Alias for is_probably_prime
    pub fn is_prime(&self, k: usize) -> bool {
        self.is_probably_prime(k)
    }
}

// ============================================================================
// DEFAULT AND DISPLAY
// ============================================================================

impl Default for BigUint {
    fn default() -> Self {
        Self::zero()
    }
}

impl core::fmt::Display for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }

        // Convert to decimal digits
        let mut digits = Vec::new();
        let mut n = self.clone();
        let ten = Self::from_u64(10);

        while !n.is_zero() {
            let (q, r) = n.div_rem(&ten);
            digits.push((r.limbs[0] as u8) + b'0');
            n = q;
        }

        digits.reverse();

        for d in digits {
            write!(f, "{}", d as char)?;
        }

        Ok(())
    }
}

impl core::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BigUint(0x{})", self.to_hex())
    }
}

impl core::fmt::LowerHex for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Constructor Tests
    // ========================================================================

    #[test]
    fn test_zero() {
        let z = BigUint::zero();
        assert!(z.is_zero());
        assert!(!z.is_one());
        assert_eq!(z.bits(), 0);
    }

    #[test]
    fn test_one() {
        let one = BigUint::one();
        assert!(!one.is_zero());
        assert!(one.is_one());
        assert_eq!(one.bits(), 1);
    }

    #[test]
    fn test_from_u64() {
        let n = BigUint::from_u64(0x123456789ABCDEF0);
        assert_eq!(n.limbs.len(), 1);
        assert_eq!(n.limbs[0], 0x123456789ABCDEF0);
    }

    #[test]
    fn test_from_u128() {
        let n = BigUint::from_u128(0x123456789ABCDEF0_FEDCBA9876543210);
        assert_eq!(n.limbs.len(), 2);
        assert_eq!(n.limbs[0], 0xFEDCBA9876543210);
        assert_eq!(n.limbs[1], 0x123456789ABCDEF0);
    }

    #[test]
    fn test_from_bytes_be() {
        let n = BigUint::from_bytes_be(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(n.limbs[0], 0x12345678);

        let n = BigUint::from_bytes_be(&[0x00, 0x00, 0x12, 0x34]);
        assert_eq!(n.limbs[0], 0x1234);

        let n = BigUint::from_bytes_be(&[]);
        assert!(n.is_zero());
    }

    #[test]
    fn test_from_bytes_le() {
        let n = BigUint::from_bytes_le(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(n.limbs[0], 0x12345678);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = BigUint::from_u128(0x123456789ABCDEF0_FEDCBA9876543210);
        let bytes_be = original.to_bytes_be();
        let restored_be = BigUint::from_bytes_be(&bytes_be);
        assert_eq!(original, restored_be);

        let bytes_le = original.to_bytes_le();
        let restored_le = BigUint::from_bytes_le(&bytes_le);
        assert_eq!(original, restored_le);
    }

    #[test]
    fn test_from_hex() {
        let n = BigUint::from_hex("0x1234ABCD").unwrap();
        assert_eq!(n.limbs[0], 0x1234ABCD);

        let n = BigUint::from_hex("DEADBEEF").unwrap();
        assert_eq!(n.limbs[0], 0xDEADBEEF);

        let n = BigUint::from_hex("0").unwrap();
        assert!(n.is_zero());

        assert!(BigUint::from_hex("GHIJ").is_none());
    }

    // ========================================================================
    // Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_add() {
        let a = BigUint::from_u64(100);
        let b = BigUint::from_u64(200);
        let c = &a + &b;
        assert_eq!(c.limbs[0], 300);

        // Test carry
        let a = BigUint::from_u64(u64::MAX);
        let b = BigUint::from_u64(1);
        let c = &a + &b;
        assert_eq!(c.limbs.len(), 2);
        assert_eq!(c.limbs[0], 0);
        assert_eq!(c.limbs[1], 1);
    }

    #[test]
    fn test_sub() {
        let a = BigUint::from_u64(300);
        let b = BigUint::from_u64(100);
        let c = &a - &b;
        assert_eq!(c.limbs[0], 200);

        // Multi-limb subtraction
        let a = BigUint::from_u128(1u128 << 64);
        let b = BigUint::from_u64(1);
        let c = &a - &b;
        assert_eq!(c.limbs[0], u64::MAX);
        assert_eq!(c.limbs.len(), 1);
    }

    #[test]
    fn test_mul() {
        let a = BigUint::from_u64(12345);
        let b = BigUint::from_u64(67890);
        let c = &a * &b;
        assert_eq!(c.limbs[0], 12345u64 * 67890);

        // Multi-limb multiplication
        let a = BigUint::from_u64(u64::MAX);
        let b = BigUint::from_u64(u64::MAX);
        let c = &a * &b;
        // (2^64 - 1)^2 = 2^128 - 2^65 + 1
        let expected = BigUint::from_u128((u64::MAX as u128) * (u64::MAX as u128));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_div_rem() {
        let a = BigUint::from_u64(1000);
        let b = BigUint::from_u64(7);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q.limbs[0], 142);
        assert_eq!(r.limbs[0], 6);

        // Verify: a = q * b + r
        let check = &(&q * &b) + &r;
        assert_eq!(a, check);
    }

    #[test]
    fn test_div_rem_large() {
        // Test with multi-limb numbers
        let a = BigUint::from_u128(0x123456789ABCDEF0_0000000000000000);
        let b = BigUint::from_u64(0x12345678);
        let (q, r) = a.div_rem(&b);

        // Verify: a = q * b + r
        let check = &(&q * &b) + &r;
        assert_eq!(a, check);
    }

    // ========================================================================
    // Bit Operation Tests
    // ========================================================================

    #[test]
    fn test_bits() {
        assert_eq!(BigUint::zero().bits(), 0);
        assert_eq!(BigUint::one().bits(), 1);
        assert_eq!(BigUint::from_u64(255).bits(), 8);
        assert_eq!(BigUint::from_u64(256).bits(), 9);
    }

    #[test]
    fn test_shift_left() {
        let n = BigUint::from_u64(1);
        let shifted = n.shl_bits(64);
        assert_eq!(shifted.limbs.len(), 2);
        assert_eq!(shifted.limbs[0], 0);
        assert_eq!(shifted.limbs[1], 1);

        let n = BigUint::from_u64(0b1010);
        let shifted = n.shl_bits(3);
        assert_eq!(shifted.limbs[0], 0b1010000);
    }

    #[test]
    fn test_shift_right() {
        let n = BigUint::from_u128(1u128 << 64);
        let shifted = n.shr_bits(64);
        assert_eq!(shifted.limbs.len(), 1);
        assert_eq!(shifted.limbs[0], 1);

        let n = BigUint::from_u64(0b1010000);
        let shifted = n.shr_bits(3);
        assert_eq!(shifted.limbs[0], 0b1010);
    }

    #[test]
    fn test_bit_get_set() {
        let mut n = BigUint::zero();
        n.set_bit(0, true);
        assert!(n.bit(0));
        assert_eq!(n.limbs[0], 1);

        n.set_bit(63, true);
        assert!(n.bit(63));
        assert_eq!(n.limbs[0], (1u64 << 63) | 1);

        n.set_bit(64, true);
        assert!(n.bit(64));
        assert_eq!(n.limbs.len(), 2);
    }

    // ========================================================================
    // Modular Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_mod_pow() {
        // 3^10 mod 7 = 59049 mod 7 = 4
        let base = BigUint::from_u64(3);
        let exp = BigUint::from_u64(10);
        let modulus = BigUint::from_u64(7);
        let result = base.mod_pow(&exp, &modulus);
        assert_eq!(result.limbs[0], 4);

        // 2^256 mod (2^256 - 1) should be 1
        let two = BigUint::from_u64(2);
        let exp = BigUint::from_u64(256);
        let m = BigUint::one().shl_bits(256).sub_u64(1).unwrap(); // 2^256 - 1
        let result = two.mod_pow(&exp, &m);
        assert!(result.is_one());
    }

    #[test]
    fn test_mod_inverse() {
        // 3 * 5 ≡ 1 (mod 7), so 3^(-1) ≡ 5 (mod 7)
        let a = BigUint::from_u64(3);
        let m = BigUint::from_u64(7);
        let inv = a.mod_inverse(&m).unwrap();
        assert_eq!(inv.limbs[0], 5);

        // Verify: a * inv ≡ 1 (mod m)
        let product = (&a * &inv) % &m;
        assert!(product.is_one());
    }

    #[test]
    fn test_mod_inverse_no_inverse() {
        // gcd(4, 8) = 4 ≠ 1, so no inverse exists
        let a = BigUint::from_u64(4);
        let m = BigUint::from_u64(8);
        assert!(a.mod_inverse(&m).is_none());
    }

    #[test]
    fn test_gcd() {
        let a = BigUint::from_u64(48);
        let b = BigUint::from_u64(18);
        let g = a.gcd(&b);
        assert_eq!(g.limbs[0], 6);

        let a = BigUint::from_u64(17);
        let b = BigUint::from_u64(13);
        let g = a.gcd(&b);
        assert!(g.is_one());
    }

    // ========================================================================
    // Primality Tests
    // ========================================================================

    #[test]
    fn test_is_prime_small() {
        assert!(!BigUint::from_u64(0).is_probably_prime(10));
        assert!(!BigUint::from_u64(1).is_probably_prime(10));
        assert!(BigUint::from_u64(2).is_probably_prime(10));
        assert!(BigUint::from_u64(3).is_probably_prime(10));
        assert!(!BigUint::from_u64(4).is_probably_prime(10));
        assert!(BigUint::from_u64(5).is_probably_prime(10));
        assert!(BigUint::from_u64(7).is_probably_prime(10));
        assert!(!BigUint::from_u64(9).is_probably_prime(10));
        assert!(BigUint::from_u64(11).is_probably_prime(10));
    }

    #[test]
    fn test_is_prime_larger() {
        // Mersenne prime 2^61 - 1
        let m61 = BigUint::from_u64((1u64 << 61) - 1);
        assert!(m61.is_probably_prime(20));

        // Not prime: 2^61 - 3
        let not_prime = BigUint::from_u64((1u64 << 61) - 3);
        assert!(!not_prime.is_probably_prime(20));
    }

    // ========================================================================
    // Comparison Tests
    // ========================================================================

    #[test]
    fn test_comparison() {
        let a = BigUint::from_u64(100);
        let b = BigUint::from_u64(200);

        assert!(a < b);
        assert!(b > a);
        assert!(a <= a);
        assert!(a >= a);
        assert!(a == a);
        assert!(a != b);
    }

    #[test]
    fn test_ct_eq() {
        let a = BigUint::from_u64(12345);
        let b = BigUint::from_u64(12345);
        let c = BigUint::from_u64(12346);

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    // ========================================================================
    // Display Tests
    // ========================================================================

    #[test]
    fn test_display() {
        use alloc::format;

        assert_eq!(format!("{}", BigUint::zero()), "0");
        assert_eq!(format!("{}", BigUint::from_u64(12345)), "12345");
    }

    #[test]
    fn test_hex_display() {
        let n = BigUint::from_u64(0xDEADBEEF);
        assert_eq!(n.to_hex(), "deadbeef");
    }
}
