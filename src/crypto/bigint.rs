//! Big integer arithmetic for cryptographic operations

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::{Add, Sub, Mul, Div, Rem};

/// Arbitrary precision unsigned integer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigUint {
    /// Little-endian limbs (least significant first)
    pub limbs: Vec<u64>,
}

impl BigUint {
    /// Create a new BigUint with value 0
    pub fn new() -> Self {
        Self { limbs: vec![0] }
    }
    
    /// Create BigUint from a single u64
    pub fn from_u64(val: u64) -> Self {
        if val == 0 {
            Self::new()
        } else {
            Self { limbs: vec![val] }
        }
    }
    
    /// Create BigUint from bytes (big-endian)
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::new();
        }
        
        let mut limbs = Vec::new();
        let mut i = bytes.len();
        
        while i > 0 {
            let start = if i >= 8 { i - 8 } else { 0 };
            let mut limb = 0u64;
            
            for j in start..i {
                limb = (limb << 8) | (bytes[j] as u64);
            }
            
            limbs.push(limb);
            i = start;
        }
        
        // Remove leading zeros
        while limbs.len() > 1 && limbs[limbs.len() - 1] == 0 {
            limbs.pop();
        }
        
        Self { limbs }
    }
    
    /// Create BigUint from bytes (little-endian)
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::new();
        }
        
        let mut limbs = Vec::new();
        let mut i = 0;
        
        while i < bytes.len() {
            let mut limb = 0u64;
            let end = core::cmp::min(i + 8, bytes.len());
            
            for j in (i..end).rev() {
                limb = (limb << 8) | (bytes[j] as u64);
            }
            
            limbs.push(limb);
            i += 8;
        }
        
        // Remove leading zeros
        while limbs.len() > 1 && limbs[limbs.len() - 1] == 0 {
            limbs.pop();
        }
        
        Self { limbs }
    }
    
    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        
        let mut bytes = Vec::new();
        
        for &limb in self.limbs.iter().rev() {
            let limb_bytes = limb.to_be_bytes();
            if bytes.is_empty() {
                // Skip leading zeros in significant limb
                let mut start = 0;
                while start < 8 && limb_bytes[start] == 0 {
                    start += 1;
                }
                bytes.extend_from_slice(&limb_bytes[start..]);
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
    
    /// Convert to bytes (little-endian)
    pub fn to_bytes_le(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        
        let mut bytes = Vec::new();
        
        for &limb in &self.limbs {
            let limb_bytes = limb.to_le_bytes();
            bytes.extend_from_slice(&limb_bytes);
        }
        
        // Remove trailing zeros
        while bytes.len() > 1 && bytes[bytes.len() - 1] == 0 {
            bytes.pop();
        }
        
        bytes
    }
    
    /// Check if BigUint is zero
    pub fn is_zero(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 0
    }
    
    /// Check if BigUint is one
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }
    
    /// Check if BigUint is odd
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }
    
    /// Check if BigUint is even
    pub fn is_even(&self) -> bool {
        !self.is_odd()
    }
    
    /// Get the number of bits in this BigUint
    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        
        let leading_limb = self.limbs[self.limbs.len() - 1];
        (self.limbs.len() - 1) * 64 + (64 - leading_limb.leading_zeros() as usize)
    }
    
    /// Left shift by one bit
    pub fn shl_1(&self) -> Self {
        let mut result = vec![0u64; self.limbs.len() + 1];
        let mut carry = 0u64;
        
        for i in 0..self.limbs.len() {
            let new_carry = self.limbs[i] >> 63;
            result[i] = (self.limbs[i] << 1) | carry;
            carry = new_carry;
        }
        
        if carry != 0 {
            result[self.limbs.len()] = carry;
        } else {
            result.pop();
        }
        
        Self { limbs: result }
    }
    
    /// Right shift by one bit
    pub fn shr_1(&self) -> Self {
        if self.is_zero() {
            return self.clone();
        }
        
        let mut result = vec![0u64; self.limbs.len()];
        let mut carry = 0u64;
        
        for i in (0..self.limbs.len()).rev() {
            let new_carry = (self.limbs[i] & 1) << 63;
            result[i] = (self.limbs[i] >> 1) | carry;
            carry = new_carry;
        }
        
        // Remove leading zero if present
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        Self { limbs: result }
    }
    
    /// Left shift by n bits
    pub fn shl(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }
        
        let limb_shift = n / 64;
        let bit_shift = n % 64;
        
        let mut result = vec![0u64; self.limbs.len() + limb_shift + 1];
        
        if bit_shift == 0 {
            for i in 0..self.limbs.len() {
                result[i + limb_shift] = self.limbs[i];
            }
        } else {
            let mut carry = 0u64;
            for i in 0..self.limbs.len() {
                let limb = self.limbs[i];
                result[i + limb_shift] = (limb << bit_shift) | carry;
                carry = limb >> (64 - bit_shift);
            }
            
            if carry != 0 {
                result[self.limbs.len() + limb_shift] = carry;
            }
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        Self { limbs: result }
    }
    
    /// Right shift by n bits
    pub fn shr(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }
        
        let limb_shift = n / 64;
        let bit_shift = n % 64;
        
        if limb_shift >= self.limbs.len() {
            return Self::new();
        }
        
        let new_len = self.limbs.len() - limb_shift;
        let mut result = vec![0u64; new_len];
        
        if bit_shift == 0 {
            for i in 0..new_len {
                result[i] = self.limbs[i + limb_shift];
            }
        } else {
            let mut carry = 0u64;
            for i in (0..new_len).rev() {
                let limb = self.limbs[i + limb_shift];
                result[i] = (limb >> bit_shift) | carry;
                carry = limb << (64 - bit_shift);
            }
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        Self { limbs: result }
    }
    
    /// Modular exponentiation: self^exp mod modulus
    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            panic!("Division by zero in modular exponentiation");
        }
        
        if exp.is_zero() {
            return Self::from_u64(1);
        }
        
        let mut result = Self::from_u64(1);
        let mut base = self % modulus;
        let mut exponent = exp.clone();
        
        while !exponent.is_zero() {
            if exponent.is_odd() {
                result = (&result * &base) % modulus.clone();
            }
            base = (&base * &base) % modulus.clone();
            exponent = exponent.shr_1();
        }
        
        result
    }
    
    /// Modular inverse using extended Euclidean algorithm
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() || modulus.is_zero() {
            return None;
        }
        
        let mut old_r = modulus.clone();
        let mut r = self.clone();
        let mut old_s = Self::new();
        let mut s = Self::from_u64(1);
        
        while !r.is_zero() {
            let (quotient, remainder) = old_r.div_rem(&r);
            
            old_r = r;
            r = remainder;
            
            let temp = old_s;
            old_s = s.clone();
            
            let product = &quotient * &s;
            if temp >= product {
                s = &temp - &product;
            } else {
                // Handle negative result by adding modulus
                s = modulus - &(&product - &temp);
            }
        }
        
        if old_r.is_one() {
            Some(old_s % modulus.clone())
        } else {
            None
        }
    }
    
    /// Greatest Common Divisor using Euclidean algorithm
    pub fn gcd(&self, other: &Self) -> Self {
        let mut a = self.clone();
        let mut b = other.clone();
        
        while !b.is_zero() {
            let temp = b.clone();
            b = &a % &b;
            a = temp;
        }
        
        a
    }
    
    /// Least Common Multiple
    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() && other.is_zero() {
            return Self::new();
        }
        
        let gcd = self.gcd(other);
        (self * other) / gcd
    }
    
    /// Check if this number is probably prime using Miller-Rabin test
    pub fn is_prime(&self, k: usize) -> bool {
        if *self <= Self::from_u64(1) {
            return false;
        }
        if *self <= Self::from_u64(3) {
            return true;
        }
        if self.is_even() {
            return false;
        }
        
        // Write self - 1 as d * 2^r
        let self_minus_1 = self - &Self::from_u64(1);
        let mut d = self_minus_1.clone();
        let mut r = 0usize;
        
        while d.is_even() {
            d = d.shr_1();
            r += 1;
        }
        
        // Witness loop
        for _ in 0..k {
            let a = Self::random_range(&Self::from_u64(2), &self_minus_1);
            let mut x = a.mod_pow(&d, self);
            
            if x.is_one() || x == self_minus_1 {
                continue;
            }
            
            let mut composite = true;
            for _ in 0..r-1 {
                x = x.mod_pow(&Self::from_u64(2), self);
                if x == self_minus_1 {
                    composite = false;
                    break;
                }
            }
            
            if composite {
                return false;
            }
        }
        
        true
    }
    
    /// Generate random BigUint in range [min, max)
    pub fn random_range(min: &Self, max: &Self) -> Self {
        if min >= max {
            return min.clone();
        }
        
        let range = max - min;
        let range_bits = range.bits();
        let range_bytes = (range_bits + 7) / 8;
        
        // Generate random bytes
        let random_bytes = super::entropy::get_entropy(range_bytes);
        let mut random_val = Self::from_bytes_be(&random_bytes);
        
        // Reduce to range
        random_val = &random_val % &range;
        min + &random_val
    }
    
    /// Division with remainder
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }
        
        if self < divisor {
            return (Self::new(), self.clone());
        }
        
        if divisor.is_one() {
            return (self.clone(), Self::new());
        }
        
        // Long division algorithm
        let mut quotient = Self::new();
        let mut remainder = Self::new();
        
        for i in (0..self.bits()).rev() {
            remainder = remainder.shl_1();
            if self.bit(i) {
                remainder = &remainder + &Self::from_u64(1);
            }
            
            if remainder >= *divisor {
                remainder = &remainder - divisor;
                quotient = quotient | &Self::from_u64(1).shl(i);
            }
        }
        
        (quotient, remainder)
    }
    
    /// Get the i-th bit (0 = least significant)
    pub fn bit(&self, i: usize) -> bool {
        let limb_index = i / 64;
        let bit_index = i % 64;
        
        if limb_index >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_index] >> bit_index) & 1 == 1
        }
    }
    
    /// Set the i-th bit
    pub fn set_bit(&mut self, i: usize, value: bool) {
        let limb_index = i / 64;
        let bit_index = i % 64;
        
        // Extend limbs if necessary
        while limb_index >= self.limbs.len() {
            self.limbs.push(0);
        }
        
        if value {
            self.limbs[limb_index] |= 1u64 << bit_index;
        } else {
            self.limbs[limb_index] &= !(1u64 << bit_index);
        }
    }
    
    /// Count trailing zeros
    pub fn trailing_zeros(&self) -> usize {
        let mut count = 0;
        
        for &limb in &self.limbs {
            if limb == 0 {
                count += 64;
            } else {
                count += limb.trailing_zeros() as usize;
                break;
            }
        }
        
        count
    }
    
    /// Count leading zeros
    pub fn leading_zeros(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        
        let total_bits = self.limbs.len() * 64;
        let actual_bits = self.bits();
        total_bits - actual_bits
    }
}

// Implement comparison traits
impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare number of limbs first
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                // Same number of limbs, compare from most significant
                for i in (0..self.limbs.len()).rev() {
                    match self.limbs[i].cmp(&other.limbs[i]) {
                        Ordering::Equal => continue,
                        other_ordering => return other_ordering,
                    }
                }
                Ordering::Equal
            }
            other_ordering => other_ordering,
        }
    }
}

// Implement arithmetic operations
impl Add<&BigUint> for &BigUint {
    type Output = BigUint;
    
    fn add(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        
        for i in 0..max_len {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            
            let (sum, overflow1) = a.overflowing_add(b);
            let (sum, overflow2) = sum.overflowing_add(carry);
            
            result.push(sum);
            carry = (overflow1 as u64) + (overflow2 as u64);
        }
        
        if carry != 0 {
            result.push(carry);
        }
        
        BigUint { limbs: result }
    }
}

impl Add<BigUint> for BigUint {
    type Output = BigUint;
    
    fn add(self, other: BigUint) -> BigUint {
        &self + &other
    }
}

impl Sub<&BigUint> for &BigUint {
    type Output = BigUint;
    
    fn sub(self, other: &BigUint) -> BigUint {
        if self < other {
            panic!("Subtraction underflow");
        }
        
        let mut result = self.limbs.clone();
        let mut borrow = 0u64;
        
        for i in 0..result.len() {
            let other_val = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            
            let (diff, underflow1) = result[i].overflowing_sub(other_val);
            let (diff, underflow2) = diff.overflowing_sub(borrow);
            
            result[i] = diff;
            borrow = (underflow1 as u64) + (underflow2 as u64);
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
}

impl Sub<BigUint> for BigUint {
    type Output = BigUint;
    
    fn sub(self, other: BigUint) -> BigUint {
        &self - &other
    }
}

impl Mul<&BigUint> for &BigUint {
    type Output = BigUint;
    
    fn mul(self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::new();
        }
        
        let mut result = vec![0u64; self.limbs.len() + other.limbs.len()];
        
        for i in 0..self.limbs.len() {
            let mut carry = 0u64;
            for j in 0..other.limbs.len() {
                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128) + 
                             (result[i + j] as u128) + (carry as u128);
                
                result[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            
            if carry != 0 {
                result[i + other.limbs.len()] = carry;
            }
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
}

impl Mul<BigUint> for BigUint {
    type Output = BigUint;
    
    fn mul(self, other: BigUint) -> BigUint {
        &self * &other
    }
}

impl Div<&BigUint> for &BigUint {
    type Output = BigUint;
    
    fn div(self, other: &BigUint) -> BigUint {
        self.div_rem(other).0
    }
}

impl Div<BigUint> for BigUint {
    type Output = BigUint;
    
    fn div(self, other: BigUint) -> BigUint {
        &self / &other
    }
}

impl Rem<&BigUint> for &BigUint {
    type Output = BigUint;
    
    fn rem(self, other: &BigUint) -> BigUint {
        self.div_rem(other).1
    }
}

impl Rem<BigUint> for BigUint {
    type Output = BigUint;
    
    fn rem(self, other: BigUint) -> BigUint {
        &self % &other
    }
}

// Bitwise OR operation
impl core::ops::BitOr<&BigUint> for BigUint {
    type Output = BigUint;
    
    fn bitor(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = Vec::with_capacity(max_len);
        
        for i in 0..max_len {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            result.push(a | b);
        }
        
        BigUint { limbs: result }
    }
}

// Default implementation
impl Default for BigUint {
    fn default() -> Self {
        Self::new()
    }
}

// Display implementation for debugging
impl core::fmt::Display for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        
        let mut digits = Vec::new();
        let mut n = self.clone();
        let ten = BigUint::from_u64(10);
        
        while !n.is_zero() {
            let (quotient, remainder) = n.div_rem(&ten);
            digits.push((remainder.limbs[0] as u8) + b'0');
            n = quotient;
        }
        
        digits.reverse();
        let s = core::str::from_utf8(&digits).map_err(|_| core::fmt::Error)?;
        write!(f, "{}", s)
    }
}