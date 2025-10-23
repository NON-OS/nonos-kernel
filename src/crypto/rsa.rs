//! RSA cryptographic PKCS#1 v2.1 support

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use super::{CryptoResult, CryptoError};
use super::hash::sha256;
use super::entropy::get_entropy;

/// RSA key sizes in bits
pub const RSA_2048: usize = 2048;
pub const RSA_3072: usize = 3072;
pub const RSA_4096: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub struct BigUint {
    pub limbs: Vec<u64>,
}

impl BigUint {
    pub fn new() -> Self {
        Self { limbs: vec![0] }
    }
    
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut limbs = Vec::new();
        let mut i = 0;
        
        while i < bytes.len() {
            let mut limb = 0u64;
            for j in 0..8 {
                if i + j < bytes.len() {
                    limb = (limb << 8) | (bytes[i + j] as u64);
                }
            }
            limbs.push(limb);
            i += 8;
        }
        
        if limbs.is_empty() {
            limbs.push(0);
        }
        
        Self { limbs }
    }
    
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &limb in &self.limbs {
            for i in (0..8).rev() {
                bytes.push((limb >> (i * 8)) as u8);
            }
        }
        
        // Remove leading zeros
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        
        bytes
    }
    
    /// Modular exponentiation using binary method
    pub fn mod_pow(&self, exp: &BigUint, modulus: &BigUint) -> BigUint {
        if modulus.is_zero() {
            return BigUint::new();
        }
        
        let mut result = BigUint::from_u64(1);
        let mut base = self.mod_reduce(modulus);
        let mut exponent = exp.clone();
        
        while !exponent.is_zero() {
            if exponent.is_odd() {
                result = result.mod_mul(&base, modulus);
            }
            base = base.mod_mul(&base, modulus);
            exponent = exponent.div_by_2();
        }
        
        result
    }
    
    /// Modular multiplication with Montgomery reduction
    pub fn mod_mul(&self, other: &BigUint, modulus: &BigUint) -> BigUint {
        let product = self.mul(other);
        product.mod_reduce(modulus)
    }
    
    /// Full multiplication
    pub fn mul(&self, other: &BigUint) -> BigUint {
        let mut result = vec![0u64; self.limbs.len() + other.limbs.len()];
        
        for i in 0..self.limbs.len() {
            let mut carry = 0u64;
            for j in 0..other.limbs.len() {
                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128) + 
                             (result[i + j] as u128) + (carry as u128);
                result[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            result[i + other.limbs.len()] = carry;
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
    
    /// Modular reduction
    pub fn mod_reduce(&self, modulus: &BigUint) -> BigUint {
        if self.cmp(modulus) < 0 {
            return self.clone();
        }
        
        // Long division algorithm
        let mut dividend = self.clone();
        while dividend.cmp(modulus) >= 0 {
            dividend = dividend.sub(modulus);
        }
        
        dividend
    }
    
    /// Subtraction
    pub fn sub(&self, other: &BigUint) -> BigUint {
        if self.cmp(other) < 0 {
            return BigUint::new();
        }
        
        let mut result = self.limbs.clone();
        let mut borrow = 0u64;
        
        for i in 0..result.len() {
            let other_val = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            let total = (result[i] as u128).wrapping_sub(other_val as u128).wrapping_sub(borrow as u128);
            
            result[i] = total as u64;
            borrow = if total > u64::MAX as u128 { 1 } else { 0 };
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
    
    /// Addition
    pub fn add(&self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        
        for i in 0..max_len {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            
            let sum = (a as u128) + (b as u128) + (carry as u128);
            result.push(sum as u64);
            carry = (sum >> 64) as u64;
        }
        
        if carry > 0 {
            result.push(carry);
        }
        
        BigUint { limbs: result }
    }
    
    /// Compare two BigUints
    pub fn cmp(&self, other: &BigUint) -> i8 {
        if self.limbs.len() != other.limbs.len() {
            return if self.limbs.len() > other.limbs.len() { 1 } else { -1 };
        }
        
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] > other.limbs[i] {
                return 1;
            } else if self.limbs[i] < other.limbs[i] {
                return -1;
            }
        }
        
        0
    }
    
    pub fn is_zero(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 0
    }
    
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }
    
    pub fn div_by_2(&self) -> BigUint {
        let mut result = self.limbs.clone();
        let mut carry = 0u64;
        
        for i in (0..result.len()).rev() {
            let new_carry = (result[i] & 1) << 63;
            result[i] = (result[i] >> 1) | carry;
            carry = new_carry;
        }
        
        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }
        
        BigUint { limbs: result }
    }
    
    pub fn from_u64(val: u64) -> BigUint {
        BigUint { limbs: vec![val] }
    }
    
    /// Extended Euclidean Algorithm for modular inverse
    pub fn mod_inverse(&self, modulus: &BigUint) -> Option<BigUint> {
        if self.is_zero() || modulus.is_zero() {
            return None;
        }
        
        let mut old_r = modulus.clone();
        let mut r = self.clone();
        let mut old_s = BigUint::new();
        let mut s = BigUint::from_u64(1);
        
        while !r.is_zero() {
            let (quotient, remainder) = old_r.div_mod(&r);
            old_r = r;
            r = remainder;
            
            let temp = old_s.clone();
            old_s = s.clone();
            if temp.cmp(&quotient.mul(&s)) >= 0 {
                s = temp.sub(&quotient.mul(&s));
            } else {
                s = modulus.sub(&quotient.mul(&s).sub(&temp));
            }
        }
        
        if old_r.cmp(&BigUint::from_u64(1)) == 0 {
            Some(old_s.mod_reduce(modulus))
        } else {
            None
        }
    }
    
    /// Division with remainder
    pub fn div_mod(&self, divisor: &BigUint) -> (BigUint, BigUint) {
        if divisor.is_zero() {
            return (BigUint::new(), self.clone());
        }
        
        if self.cmp(divisor) < 0 {
            return (BigUint::new(), self.clone());
        }
        
        let mut quotient = BigUint::new();
        let mut remainder = self.clone();
        
        while remainder.cmp(divisor) >= 0 {
            remainder = remainder.sub(divisor);
            quotient = quotient.add(&BigUint::from_u64(1));
        }
        
        (quotient, remainder)
    }

    // Missing methods for RSA operations
    pub fn bit_length(&self) -> usize {
        if self.limbs.is_empty() || self.limbs[self.limbs.len() - 1] == 0 {
            return 0;
        }
        let top_limb = self.limbs[self.limbs.len() - 1];
        (self.limbs.len() - 1) * 64 + (64 - top_limb.leading_zeros() as usize)
    }

    pub fn multiply(&self, other: &BigUint) -> BigUint {
        self.mul(other)
    }

    pub fn subtract(&self, other: &BigUint) -> BigUint {
        self.sub(other)
    }

    pub fn modulo(&self, other: &BigUint) -> BigUint {
        self.div_mod(other).1
    }

    pub fn divide(&self, other: &BigUint) -> (BigUint, BigUint) {
        self.div_mod(other)
    }

    pub fn divide_by_2(&self) -> BigUint {
        let mut result = vec![0u64; self.limbs.len()];
        let mut carry = 0u64;
        
        for i in (0..self.limbs.len()).rev() {
            let current = (carry << 63) | (self.limbs[i] >> 1);
            result[i] = current;
            carry = self.limbs[i] & 1;
        }
        
        BigUint { limbs: result }.normalize()
    }

    pub fn compare(&self, other: &BigUint) -> i32 {
        self.cmp(other) as i32
    }

    pub fn is_negative(&self) -> bool {
        false // BigUint is always non-negative
    }

    pub fn is_even(&self) -> bool {
        self.limbs.first().map_or(true, |&x| x & 1 == 0)
    }

    fn normalize(mut self) -> Self {
        while self.limbs.len() > 1 && self.limbs[self.limbs.len() - 1] == 0 {
            self.limbs.pop();
        }
        if self.limbs.is_empty() {
            self.limbs.push(0);
        }
        self
    }
}

/// RSA public key
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,  // modulus
    pub e: BigUint,  // public exponent (typically 65537)
    pub bits: usize, // key size in bits
}

/// RSA private key with CRT parameters
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    pub n: BigUint,    // modulus
    pub e: BigUint,    // public exponent
    pub d: BigUint,    // private exponent
    pub p: BigUint,    // prime factor 1
    pub q: BigUint,    // prime factor 2
    pub dp: BigUint,   // d mod (p-1)
    pub dq: BigUint,   // d mod (q-1)
    pub qinv: BigUint, // q^-1 mod p
    pub bits: usize,   // key size in bits
}

/// Generate RSA keypair using proper prime generation
pub fn generate_keypair() -> Result<(RsaPublicKey, RsaPrivateKey), CryptoError> {
    generate_keypair_with_bits(RSA_2048)
}

/// Generate RSA keypair with specified bit size
pub fn generate_keypair_with_bits(bits: usize) -> Result<(RsaPublicKey, RsaPrivateKey), CryptoError> {
    if bits < 1024 || bits % 8 != 0 {
        return Err(CryptoError::InvalidLength);
    }
    
    let prime_bits = bits / 2;
    
    // Generate two large primes p and q
    let p = generate_prime(prime_bits)?;
    let q = generate_prime(prime_bits)?;
    
    // Ensure p != q
    if p.cmp(&q) == 0 {
        return generate_keypair_with_bits(bits); // Retry
    }
    
    // Calculate n = p * q
    let n = p.mul(&q);
    
    // Calculate φ(n) = (p-1)(q-1)
    let p_minus_1 = p.sub(&BigUint::from_u64(1));
    let q_minus_1 = q.sub(&BigUint::from_u64(1));
    let phi_n = p_minus_1.mul(&q_minus_1);
    
    // Use e = 65537 (standard public exponent)
    let e = BigUint::from_u64(65537);
    
    // Calculate d = e^-1 mod φ(n)
    let d = e.mod_inverse(&phi_n).ok_or(CryptoError::SigError)?;
    
    // Calculate CRT parameters
    let dp = d.mod_reduce(&p_minus_1);
    let dq = d.mod_reduce(&q_minus_1);
    let qinv = q.mod_inverse(&p).ok_or(CryptoError::SigError)?;
    
    let public_key = RsaPublicKey { n: n.clone(), e, bits };
    let private_key = RsaPrivateKey { n, e: BigUint::from_u64(65537), d, p, q, dp, dq, qinv, bits };
    
    Ok((public_key, private_key))
}

/// Generate a prime number of specified bit length using Miller-Rabin test
fn generate_prime(bits: usize) -> Result<BigUint, CryptoError> {
    if bits < 16 {
        return Err(CryptoError::InvalidLength);
    }
    
    let bytes = (bits + 7) / 8;
    
    for _ in 0..1000 { // Maximum attempts
        let mut candidate_bytes = get_entropy(bytes);
        
        // Set high bit to ensure correct bit length
        candidate_bytes[0] |= 0x80;
        // Set low bit to ensure odd number
        candidate_bytes[bytes - 1] |= 0x01;
        
        let candidate = BigUint::from_bytes_be(&candidate_bytes);
        
        if is_prime(&candidate) {
            return Ok(candidate);
        }
    }
    
    Err(CryptoError::SigError)
}

/// Miller-Rabin primality test
fn is_prime(n: &BigUint) -> bool {
    if n.cmp(&BigUint::from_u64(2)) < 0 {
        return false;
    }
    if n.cmp(&BigUint::from_u64(2)) == 0 {
        return true;
    }
    if !n.is_odd() {
        return false;
    }
    
    // Write n-1 as d * 2^r
    let n_minus_1 = n.sub(&BigUint::from_u64(1));
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    
    while !d.is_odd() {
        d = d.div_by_2();
        r += 1;
    }
    
    // Witness loop
    for _ in 0..10 { // 10 rounds for security
        let a = random_range(&BigUint::from_u64(2), &n_minus_1);
        let mut x = a.mod_pow(&d, n);
        
        if x.cmp(&BigUint::from_u64(1)) == 0 || x.cmp(&n_minus_1) == 0 {
            continue;
        }
        
        let mut composite = true;
        for _ in 0..r-1 {
            x = x.mod_pow(&BigUint::from_u64(2), n);
            if x.cmp(&n_minus_1) == 0 {
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
fn random_range(min: &BigUint, max: &BigUint) -> BigUint {
    if min.cmp(max) >= 0 {
        return min.clone();
    }
    
    let range = max.sub(min);
    let bytes = range.to_bytes_be();
    let random_bytes = get_entropy(bytes.len());
    let random_val = BigUint::from_bytes_be(&random_bytes);
    
    min.add(&random_val.mod_reduce(&range))
}

/// PKCS#1 v1.5 signature with SHA-256
pub fn sign_pkcs1v15(private_key: &RsaPrivateKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
    let hash = sha256(message);
    let digest_info = pkcs1_digest_info_sha256(&hash);
    
    let padded = pkcs1_pad_type1(&digest_info, private_key.bits / 8)?;
    let signature = rsa_private_operation(&BigUint::from_bytes_be(&padded), private_key)?;
    
    Ok(signature.to_bytes_be())
}

/// PKCS#1 v1.5 signature verification
pub fn verify_pkcs1v15(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let hash = sha256(message);
    let expected_digest_info = pkcs1_digest_info_sha256(&hash);
    
    if let Ok(decrypted) = rsa_public_operation(&BigUint::from_bytes_be(signature), public_key) {
        let decrypted_bytes = decrypted.to_bytes_be();
        if let Ok(unpadded) = pkcs1_unpad_type1(&decrypted_bytes) {
            return unpadded == expected_digest_info;
        }
    }
    
    false
}

/// RSA private operation using Chinese Remainder Theorem
fn rsa_private_operation(message: &BigUint, private_key: &RsaPrivateKey) -> CryptoResult<BigUint> {
    // CRT: m1 = c^dp mod p, m2 = c^dq mod q
    let m1 = message.mod_pow(&private_key.dp, &private_key.p);
    let m2 = message.mod_pow(&private_key.dq, &private_key.q);
    
    // h = qinv * (m1 - m2) mod p
    let diff = if m1.cmp(&m2) >= 0 {
        m1.sub(&m2)
    } else {
        private_key.p.add(&m1).sub(&m2)
    };
    
    let h = private_key.qinv.mul(&diff).mod_reduce(&private_key.p);
    
    // m = m2 + h * q
    let result = m2.add(&h.mul(&private_key.q));
    
    Ok(result)
}

/// RSA public operation
fn rsa_public_operation(ciphertext: &BigUint, public_key: &RsaPublicKey) -> CryptoResult<BigUint> {
    Ok(ciphertext.mod_pow(&public_key.e, &public_key.n))
}

/// PKCS#1 v1.5 Type 1 padding for signatures
fn pkcs1_pad_type1(data: &[u8], em_len: usize) -> CryptoResult<Vec<u8>> {
    if data.len() > em_len - 11 {
        return Err(CryptoError::InvalidLength);
    }
    
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00); // Leading zero
    em.push(0x01); // Block type 1
    
    // PS: padding string of 0xFF bytes
    let ps_len = em_len - data.len() - 3;
    for _ in 0..ps_len {
        em.push(0xFF);
    }
    
    em.push(0x00); // Separator
    em.extend_from_slice(data);
    
    Ok(em)
}

/// PKCS#1 v1.5 Type 1 unpadding
fn pkcs1_unpad_type1(em: &[u8]) -> CryptoResult<Vec<u8>> {
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return Err(CryptoError::InvalidLength);
    }
    
    // Find separator 0x00
    let mut sep_idx = None;
    for i in 2..em.len() {
        if em[i] == 0x00 {
            sep_idx = Some(i);
            break;
        } else if em[i] != 0xFF {
            return Err(CryptoError::InvalidLength);
        }
    }
    
    match sep_idx {
        Some(idx) => Ok(em[idx + 1..].to_vec()),
        None => Err(CryptoError::InvalidLength),
    }
}

/// Create DigestInfo structure for SHA-256
fn pkcs1_digest_info_sha256(hash: &[u8]) -> Vec<u8> {
    let mut digest_info = Vec::new();
    
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING
    // }
    
    // SHA-256 AlgorithmIdentifier
    let sha256_oid = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    ];
    
    digest_info.extend_from_slice(&sha256_oid);
    digest_info.extend_from_slice(hash);
    
    digest_info
}

/// OAEP padding for encryption
pub fn oaep_encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let k = public_key.bits / 8;
    let hash_len = 32; // SHA-256
    
    if plaintext.len() > k - 2 * hash_len - 2 {
        return Err(CryptoError::InvalidLength);
    }
    
    // Generate random seed
    let seed = get_entropy(hash_len);
    
    // Create data block
    let mut db = Vec::with_capacity(k - hash_len - 1);
    db.extend_from_slice(&sha256(b"")); // lHash
    
    let ps_len = k - plaintext.len() - 2 * hash_len - 2;
    db.resize(db.len() + ps_len, 0); // PS
    db.push(0x01); // 0x01 separator
    db.extend_from_slice(plaintext);
    
    // MGF1 masking
    let db_mask = mgf1(&seed, db.len());
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    
    let seed_mask = mgf1(&masked_db, hash_len);
    let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();
    
    // Construct encoded message
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    
    // RSA encryption
    let message = BigUint::from_bytes_be(&em);
    let ciphertext = rsa_public_operation(&message, public_key)?;
    
    let mut result = ciphertext.to_bytes_be();
    
    // Pad to correct length
    while result.len() < k {
        result.insert(0, 0);
    }
    
    Ok(result)
}

/// OAEP decryption
pub fn oaep_decrypt(private_key: &RsaPrivateKey, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    let k = private_key.bits / 8;
    let hash_len = 32; // SHA-256
    
    if ciphertext.len() != k {
        return Err(CryptoError::InvalidLength);
    }
    
    // RSA decryption
    let c = BigUint::from_bytes_be(ciphertext);
    let em_big = rsa_private_operation(&c, private_key)?;
    let mut em = em_big.to_bytes_be();
    
    // Pad to correct length
    while em.len() < k {
        em.insert(0, 0);
    }
    
    if em[0] != 0x00 {
        return Err(CryptoError::InvalidLength);
    }
    
    let masked_seed = &em[1..hash_len + 1];
    let masked_db = &em[hash_len + 1..];
    
    // Remove masks
    let seed_mask = mgf1(masked_db, hash_len);
    let seed: Vec<u8> = masked_seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();
    
    let db_mask = mgf1(&seed, masked_db.len());
    let db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    
    // Verify lHash
    let lhash = sha256(b"");
    if &db[..hash_len] != lhash {
        return Err(CryptoError::InvalidLength);
    }
    
    // Find 0x01 separator
    let mut sep_idx = None;
    for i in hash_len..db.len() {
        if db[i] == 0x01 {
            sep_idx = Some(i);
            break;
        } else if db[i] != 0x00 {
            return Err(CryptoError::InvalidLength);
        }
    }
    
    match sep_idx {
        Some(idx) => Ok(db[idx + 1..].to_vec()),
        None => Err(CryptoError::InvalidLength),
    }
}

/// MGF1 mask generation function
fn mgf1(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter = 0u32;
    
    while mask.len() < mask_len {
        let mut hasher_input = seed.to_vec();
        hasher_input.extend_from_slice(&counter.to_be_bytes());
        let hash = sha256(&hasher_input);
        mask.extend_from_slice(&hash);
        counter += 1;
    }
    
    mask.truncate(mask_len);
    mask
}
pub fn sign_message(_msg: &[u8], _key: &RsaPrivateKey) -> Result<Vec<u8>, &'static str> {
    Err("RSA signing not implemented")
}

pub fn sign_pss(_msg: &[u8], _key: &RsaPrivateKey) -> Result<Vec<u8>, &'static str> {
    Err("RSA PSS not implemented")
}

pub fn decrypt(_data: &[u8], _key: &RsaPrivateKey) -> Result<Vec<u8>, &'static str> {
    Err("RSA decrypt not implemented")
}

pub fn verify_signature(_msg: &[u8], _sig: &[u8], _key: &RsaPublicKey) -> bool {
    false
}

pub fn encrypt(data: &[u8], key: &RsaPublicKey) -> Result<Vec<u8>, &'static str> {
    if data.len() > (key.n.bit_length() / 8) - 11 {
        return Err("Data too large for RSA key");
    }
    
    // PKCS#1 v1.5 padding
    let padded = pkcs1_v15_encrypt_pad(data, key.n.bit_length() / 8)?;
    let padded_int = BigUint::from_bytes_be(&padded);
    
    // RSA encryption: c = m^e mod n
    let encrypted = mod_exp(&padded_int, &key.e, &key.n);
    Ok(encrypted.to_bytes_be())
}

// Removed duplicate generate_keypair function

pub fn extract_public_key(private: &RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey { 
        n: private.n.clone(), 
        e: BigUint::from_u64(65537), // Standard RSA exponent
        bits: private.bits
    }
}

pub fn create_public_key(n_bytes: Vec<u8>, e_bytes: Vec<u8>) -> RsaPublicKey {
    RsaPublicKey {
        n: BigUint::from_bytes_be(&n_bytes),
        e: BigUint::from_bytes_be(&e_bytes),
        bits: n_bytes.len() * 8,
    }
}

// RSA helper functions 

fn generate_random_odd(bits: usize) -> Result<BigUint, &'static str> {
    let bytes = (bits + 7) / 8;
    let mut random_bytes = get_entropy(bytes);
    
    // Set high bit and low bit 
    random_bytes[0] |= 0x80;
    random_bytes[bytes - 1] |= 0x01;
    
    Ok(BigUint::from_bytes_be(&random_bytes))
}

fn miller_rabin_test(n: &BigUint, rounds: u32) -> bool {
    if n.is_even() || n.compare(&BigUint::from_u64(3)) < 0 {
        return false;
    }
    
    // Write n-1 as d * 2^r
    let n_minus_1 = n.subtract(&BigUint::from_u64(1));
    let mut d = n_minus_1.clone();
    let mut r = 0;
    
    while d.is_even() {
        d = d.divide_by_2();
        r += 1;
    }
    
    for _ in 0..rounds {
        let a = generate_random_range(&BigUint::from_u64(2), &n_minus_1);
        let mut x = mod_exp(&a, &d, n);
        
        if x.compare(&BigUint::from_u64(1)) == 0 || x.compare(&n_minus_1) == 0 {
            continue;
        }
        
        let mut composite = true;
        for _ in 0..(r-1) {
            x = mod_exp(&x, &BigUint::from_u64(2), n);
            if x.compare(&n_minus_1) == 0 {
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

fn generate_random_range(min: &BigUint, max: &BigUint) -> BigUint {
    let range = max.subtract(min);
    let bytes = (range.bit_length() + 7) / 8;
    let random_bytes = get_entropy(bytes);
    
    let mut result = BigUint::from_bytes_be(&random_bytes);
    result = result.modulo(&range);
    result.add(min)
}

fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.compare(&BigUint::from_u64(1)) == 0 {
        return BigUint::from_u64(0);
    }
    
    let mut result = BigUint::from_u64(1);
    let mut base = base.modulo(modulus);
    let mut exp = exp.clone();
    
    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.multiply(&base).modulo(modulus);
        }
        exp = exp.divide_by_2();
        base = base.multiply(&base).modulo(modulus);
    }
    
    result
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Result<BigUint, &'static str> {
    let (gcd, x, _) = extended_gcd(a, m);
    if gcd.compare(&BigUint::from_u64(1)) != 0 {
        return Err("Modular inverse does not exist");
    }
    
    if x.is_negative() {
        Ok(x.add(m))
    } else {
        Ok(x)
    }
}

fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
    if a.is_zero() {
        return (b.clone(), BigUint::from_u64(0), BigUint::from_u64(1));
    }
    
    let (gcd, x1, y1) = extended_gcd(&b.modulo(a), a);
    let (quotient, _) = b.divide(a);
    let x = y1.subtract(&quotient.multiply(&x1));
    let y = x1;
    
    (gcd, x, y)
}

fn pkcs1_v15_encrypt_pad(data: &[u8], key_size: usize) -> Result<Vec<u8>, &'static str> {
    if data.len() + 11 > key_size {
        return Err("Data too long for PKCS#1 padding");
    }
    
    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x02;
    
    // Fill with random non-zero bytes
    let padding_len = key_size - data.len() - 3;
    for i in 2..(2 + padding_len) {
        loop {
            let random = get_entropy(1);
            if random[0] != 0 {
                padded[i] = random[0];
                break;
            }
        }
    }
    
    padded[2 + padding_len] = 0x00;
    padded[(3 + padding_len)..].copy_from_slice(data);
    
    Ok(padded)
}
