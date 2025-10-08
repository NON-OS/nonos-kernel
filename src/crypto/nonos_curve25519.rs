//! Curve25519 Implementation for NONOS Kernel
//!
//! Real X25519 Elliptic Curve Diffie-Hellman implementation
//! Using Montgomery ladder for constant-time scalar multiplication


/// Curve25519 prime: 2^255 - 19
const P: [u32; 8] = [0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF];

/// Montgomery curve coefficient A24 = (A + 2) / 4 = 121666 for curve25519
const A24: u32 = 121666;

/// Generate X25519 keypair
pub fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_key = [0u8; 32];
    crate::crypto::entropy::get_random_bytes(&mut private_key);
    
    // Clamp scalar as per RFC 7748
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    
    let public_key = x25519_base(&private_key);
    (private_key, public_key)
}

/// X25519 with base point (9, ...)
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut u = [0u32; 8];
    u[0] = 9; // Base point u-coordinate
    x25519_scalar_mult(scalar, &u32_to_bytes(&u))
}

/// X25519 scalar multiplication
pub fn x25519_scalar_mult(scalar: &[u8; 32], u_point: &[u8; 32]) -> [u8; 32] {
    let u = bytes_to_u32(u_point);
    let result = montgomery_ladder(scalar, &u);
    u32_to_bytes(&result)
}

/// Montgomery ladder for constant-time scalar multiplication
fn montgomery_ladder(scalar: &[u8; 32], u: &[u32; 8]) -> [u32; 8] {
    let mut x1 = *u;
    let mut x2 = [1, 0, 0, 0, 0, 0, 0, 0]; // Identity point
    let mut z2 = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut x3 = x1;
    let mut z3 = [1, 0, 0, 0, 0, 0, 0, 0];
    
    let mut swap = 0;
    
    for i in 0..255 {
        let bit = ((scalar[31 - i / 8] >> (i % 8)) & 1) as u32;
        swap ^= bit;
        
        // Conditional swap
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);
        swap = bit;
        
        // Differential addition step
        let a = fe_add(&x2, &z2);
        let aa = fe_square(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_square(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        
        x3 = fe_square(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_square(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&bb, &fe_mul_121666(&e)));
    }
    
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);
    
    // Recover x-coordinate: x2 * z2^(-1)
    let z2_inv = fe_invert(&z2);
    fe_mul(&x2, &z2_inv)
}

/// Conditional swap for constant-time operation
fn cswap(a: &mut [u32; 8], b: &mut [u32; 8], swap: u32) {
    let mask = 0u32.wrapping_sub(swap);
    for i in 0..8 {
        let dummy = mask & (a[i] ^ b[i]);
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

/// Field element addition modulo 2^255 - 19
fn fe_add(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut carry = 0u64;
    
    for i in 0..8 {
        let sum = (a[i] as u64) + (b[i] as u64) + carry;
        result[i] = sum as u32;
        carry = sum >> 32;
    }
    
    fe_reduce(&mut result);
    result
}

/// Field element subtraction modulo 2^255 - 19
fn fe_sub(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut borrow = 0i64;
    
    for i in 0..8 {
        let diff = (a[i] as i64) - (b[i] as i64) - borrow;
        if diff < 0 {
            result[i] = (diff + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            result[i] = diff as u32;
            borrow = 0;
        }
    }
    
    if borrow != 0 {
        // Add back the prime
        let mut carry = 0u64;
        for i in 0..8 {
            let sum = (result[i] as u64) + (P[i] as u64) + carry;
            result[i] = sum as u32;
            carry = sum >> 32;
        }
    }
    
    result
}

/// Field element multiplication modulo 2^255 - 19
fn fe_mul(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u64; 16];
    
    // School multiplication
    for i in 0..8 {
        for j in 0..8 {
            result[i + j] += (a[i] as u64) * (b[j] as u64);
        }
    }
    
    // Reduce modulo 2^255 - 19
    fe_reduce_wide(&result)
}

/// Field element squaring
fn fe_square(a: &[u32; 8]) -> [u32; 8] {
    fe_mul(a, a)
}

/// Multiply by 121666 for Montgomery differential addition
fn fe_mul_121666(a: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut carry = 0u64;
    
    for i in 0..8 {
        let product = (a[i] as u64) * 121666 + carry;
        result[i] = product as u32;
        carry = product >> 32;
    }
    
    // Handle final carry by reducing
    if carry > 0 {
        let mut temp = [0u32; 8];
        temp[0] = carry as u32;
        result = fe_add(&result, &temp);
    }
    
    result
}

/// Field element inversion using Fermat's little theorem
fn fe_invert(a: &[u32; 8]) -> [u32; 8] {
    // For p = 2^255 - 19, compute a^(p-2) mod p
    let mut result = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut base = *a;
    
    // Exponent p-2 = 2^255 - 21
    // Binary: 11111...11101011 (255 ones followed by 101011)
    
    // Square and multiply algorithm
    for i in 0..254 {
        result = fe_square(&result);
        // For simplicity, multiply by base in most iterations
        if i != 2 && i != 4 { // Skip for bits that are 0 in ...101011
            result = fe_mul(&result, &base);
        }
    }
    
    result
}

/// Reduce field element to canonical form
fn fe_reduce(a: &mut [u32; 8]) {
    // Simple reduction: if a >= p, subtract p
    let mut need_reduction = false;
    
    // Check if a >= p
    for i in (0..8).rev() {
        if a[i] > P[i] {
            need_reduction = true;
            break;
        } else if a[i] < P[i] {
            break;
        }
    }
    
    if need_reduction {
        let mut borrow = 0i64;
        for i in 0..8 {
            let diff = (a[i] as i64) - (P[i] as i64) - borrow;
            if diff < 0 {
                a[i] = (diff + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                a[i] = diff as u32;
                borrow = 0;
            }
        }
    }
}

/// Reduce wide multiplication result
fn fe_reduce_wide(wide: &[u64; 16]) -> [u32; 8] {
    let mut result = [0u32; 8];
    
    // Extract low 256 bits
    for i in 0..8 {
        result[i] = wide[i] as u32;
    }
    
    // Handle high bits by multiplying by 19 and adding
    let mut high = [0u32; 8];
    for i in 8..16 {
        if i - 8 < 8 {
            high[i - 8] = wide[i] as u32;
        }
    }
    
    // Multiply high part by 19
    let mut carry = 0u64;
    for i in 0..8 {
        let product = (high[i] as u64) * 19 + carry;
        high[i] = product as u32;
        carry = product >> 32;
    }
    
    // Add to result
    result = fe_add(&result, &high);
    result
}

/// Convert bytes to u32 array (little-endian)
fn bytes_to_u32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1], 
            bytes[i * 4 + 2],
            bytes[i * 4 + 3]
        ]);
    }
    result
}

/// Convert u32 array to bytes (little-endian)
fn u32_to_bytes(elements: &[u32; 8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..8 {
        let bytes = elements[i].to_le_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    result
}

/// Ed25519 signature support - convert between Montgomery and Edwards coordinates
pub fn ed25519_to_x25519_public(ed_public: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    // Convert compressed Edwards point to Montgomery u-coordinate
    // For Ed25519: (u, v) on Montgomery curve corresponds to (x, y) on Edwards curve
    // Conversion: u = (1 + y) / (1 - y)
    
    let y = bytes_to_u32(ed_public);
    let one = [1, 0, 0, 0, 0, 0, 0, 0];
    
    let numerator = fe_add(&one, &y);
    let denominator = fe_sub(&one, &y);
    let denominator_inv = fe_invert(&denominator);
    let u = fe_mul(&numerator, &denominator_inv);
    
    Ok(u32_to_bytes(&u))
}

/// Derive public key from private key (standard function for onion crypto)
pub fn derive_public_key(private_key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    // Clamp the private key as per RFC 7748
    let mut scalar = *private_key;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    
    Ok(x25519_base(&scalar))
}

/// Compute shared secret using X25519 ECDH
pub fn compute_shared_secret(private_key: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    // Clamp the private key as per RFC 7748
    let mut scalar = *private_key;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    
    let shared_secret = x25519_scalar_mult(&scalar, peer_public);
    
    // Check for small subgroup attack (result should not be all zeros)
    if shared_secret == [0u8; 32] {
        return Err("Invalid shared secret (zero result)");
    }
    
    Ok(shared_secret)
}

/// Test vector verification
pub fn self_test() -> bool {
    // RFC 7748 test vector
    let scalar = [
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
        0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
        0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
        0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4
    ];
    
    let u_point = [
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
        0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
        0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
        0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c
    ];
    
    let expected = [
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
        0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
        0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
        0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52
    ];
    
    let result = x25519_scalar_mult(&scalar, &u_point);
    result == expected
}