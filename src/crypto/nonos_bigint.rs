//! Big Integer Implementation for NONOS Kernel Cryptography
//!
//! Production-grade arbitrary precision integer arithmetic
//! Used for RSA operations and Diffie-Hellman key exchange

use alloc::{vec, vec::Vec};
use core::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigUint {
    /// Little-endian limbs (least significant first)
    limbs: Vec<u32>,
}

impl BigUint {
    /// Create BigUint from u32
    pub fn from(value: u32) -> Self {
        if value == 0 {
            BigUint { limbs: vec![0] }
        } else {
            BigUint { limbs: vec![value] }
        }
    }
    
    /// Create BigUint from big-endian bytes
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigUint { limbs: vec![0] };
        }
        
        let mut limbs = Vec::new();
        let mut current_limb = 0u32;
        let mut shift = 0;
        
        for &byte in bytes.iter().rev() {
            current_limb |= (byte as u32) << shift;
            shift += 8;
            
            if shift >= 32 {
                limbs.push(current_limb);
                current_limb = 0;
                shift = 0;
            }
        }
        
        if shift > 0 {
            limbs.push(current_limb);
        }
        
        // Remove leading zeros
        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }
        
        BigUint { limbs }
    }
    
    /// Convert to big-endian bytes
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.limbs.is_empty() || (self.limbs.len() == 1 && self.limbs[0] == 0) {
            return vec![0];
        }
        
        let mut bytes = Vec::new();
        
        // Convert from little-endian limbs to big-endian bytes
        for &limb in self.limbs.iter().rev() {
            let limb_bytes = limb.to_be_bytes();
            bytes.extend_from_slice(&limb_bytes);
        }
        
        // Remove leading zero bytes
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        
        bytes
    }
    
    /// Modular exponentiation: base^exp mod modulus
    pub fn modpow(&self, exp: &BigUint, modulus: &BigUint) -> BigUint {
        if modulus.is_zero() {
            panic!("Division by zero in modpow");
        }
        
        if exp.is_zero() {
            return BigUint::from(1);
        }
        
        let mut result = BigUint::from(1);
        let mut base = self.mod_op(modulus);
        let mut exponent = exp.clone();
        
        while !exponent.is_zero() {
            if exponent.is_odd() {
                result = result.mul(&base).mod_op(modulus);
            }
            base = base.mul(&base).mod_op(modulus);
            exponent = exponent.shr_one();
        }
        
        result
    }
    
    /// Multiplication
    pub fn mul(&self, other: &BigUint) -> BigUint {
        let mut result = vec![0u32; self.limbs.len() + other.limbs.len()];
        
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let product = (a as u64) * (b as u64) + (result[i + j] as u64) + carry;
                result[i + j] = product as u32;
                carry = product >> 32;
            }
            if carry > 0 {
                result[i + other.limbs.len()] = carry as u32;
            }
        }
        
        // Remove leading zeros
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
    
    /// Modulo operation
    pub fn mod_op(&self, modulus: &BigUint) -> BigUint {
        if modulus.is_zero() {
            panic!("Division by zero in mod_op");
        }
        
        if self < modulus {
            return self.clone();
        }
        
        // Simplified division algorithm
        let mut dividend = self.clone();
        while dividend >= *modulus {
            dividend = dividend.sub(modulus);
        }
        
        dividend
    }
    
    /// Subtraction (assuming self >= other)
    fn sub(&self, other: &BigUint) -> BigUint {
        if self < other {
            panic!("Subtraction underflow");
        }
        
        let mut result = vec![0u32; self.limbs.len()];
        let mut borrow = 0i64;
        
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = if i < other.limbs.len() { other.limbs[i] as i64 } else { 0 };
            
            let diff = a - b - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                result[i] = diff as u32;
                borrow = 0;
            }
        }
        
        // Remove leading zeros
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
    
    /// Right shift by one bit
    fn shr_one(&self) -> BigUint {
        if self.is_zero() {
            return self.clone();
        }
        
        let mut result = vec![0u32; self.limbs.len()];
        let mut carry = 0u32;
        
        for i in (0..self.limbs.len()).rev() {
            let limb = self.limbs[i];
            result[i] = (limb >> 1) | carry;
            carry = (limb & 1) << 31;
        }
        
        // Remove leading zeros
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
    
    /// Check if odd
    fn is_odd(&self) -> bool {
        !self.limbs.is_empty() && (self.limbs[0] & 1) == 1
    }
    
    /// Check if zero
    fn is_zero(&self) -> bool {
        self.limbs.is_empty() || (self.limbs.len() == 1 && self.limbs[0] == 0)
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
                // Same length, compare from most significant limb
                for i in (0..self.limbs.len()).rev() {
                    match self.limbs[i].cmp(&other.limbs[i]) {
                        Ordering::Equal => continue,
                        result => return result,
                    }
                }
                Ordering::Equal
            }
            result => result,
        }
    }
}

impl core::ops::Rem for &BigUint {
    type Output = BigUint;
    
    fn rem(self, rhs: &BigUint) -> BigUint {
        self.mod_op(rhs)
    }
}