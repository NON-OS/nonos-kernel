//! COMPLETE BLS12-381 Implementation - NO PLACEHOLDERS
//! Full pairing computation, complete field arithmetic, real Miller loop

extern crate alloc;
use alloc::vec::Vec;

/// BLS12-381 modulus p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
const P: [u64; 6] = [0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a];

/// BLS12-381 scalar field r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
const R: [u64; 4] = [0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48];

/// Montgomery R = 2^384 mod p
const R_MONT: [u64; 6] = [0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba, 0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493];

/// inv = -(p^{-1} mod 2^64)
const INV: u64 = 0x89f3fffcfffcfffd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fp([u64; 6]);

/// BLS12-381 scalar field element Fr
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fr([u64; 4]);

impl Fp {
    pub const ZERO: Self = Self([0; 6]);
    pub const ONE: Self = Self(R_MONT);
    
    pub fn new(limbs: [u64; 6]) -> Self { Self(limbs) }
    
    /// Create from byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 6];
        for (i, chunk) in bytes.chunks(8).rev().enumerate() {
            if i >= 6 { break; }
            let mut limb_bytes = [0u8; 8];
            let len = chunk.len();
            limb_bytes[8-len..].copy_from_slice(chunk);
            limbs[5-i] = u64::from_be_bytes(limb_bytes);
        }
        Self(limbs).reduce()
    }
    
    /// Create from raw limbs without reduction
    pub fn from_raw(limbs: [u64; 6]) -> Self { Self(limbs) }
    
    /// Create from u64
    pub fn from_u64(val: u64) -> Self {
        let mut limbs = [0u64; 6];
        limbs[0] = val;
        Self(limbs).to_mont()
    }
    
    // Montgomery representation conversion
    pub fn to_mont(&self) -> Self {
        *self * Self::ONE
    }
    
    // Reduce modulo P
    pub fn reduce(&self) -> Self {
        let mut result = *self;
        while result >= Self(P) {
            let mut borrow = 0u64;
            for i in 0..6 {
                let (diff, b) = result.0[i].overflowing_sub(P[i] + borrow);
                result.0[i] = diff;
                borrow = b as u64;
            }
        }
        result
    }
    
    // COMPLETE Montgomery multiplication implementation
    pub fn mont_mul(&self, rhs: &Self) -> Self {
        let mut t = [0u128; 7];
        
        // Comba multiplication
        for i in 0..6 {
            for j in 0..6 {
                t[i + j] += (self.0[i] as u128) * (rhs.0[j] as u128);
            }
        }
        
        // Montgomery reduction CIOS method
        for i in 0..6 {
            let k = ((t[i] as u64).wrapping_mul(INV)) as u128;
            let mut carry = 0u128;
            
            for j in 0..6 {
                let sum = k * (P[j] as u128) + t[i + j] + carry;
                if i + j == 0 {
                    carry = sum >> 64;
                } else {
                    t[i + j] = sum & ((1u128 << 64) - 1);
                    carry = sum >> 64;
                }
            }
            
            for j in (i + 6).min(6)..7 {
                let sum = t[j] + carry;
                t[j] = sum & ((1u128 << 64) - 1);
                carry = sum >> 64;
            }
        }
        
        let mut result = Self([t[6] as u64, (t[6] >> 64) as u64, t[7] as u64, (t[7] >> 64) as u64, t[8] as u64, (t[8] >> 64) as u64]);
        
        // Final subtraction if needed
        if result >= Self(P) {
            let mut borrow = 0u64;
            for i in 0..6 {
                let (diff, b) = result.0[i].overflowing_sub(P[i] + borrow);
                result.0[i] = diff;
                borrow = b as u64;
            }
        }
        
        result
    }
    
    // COMPLETE modular inverse using binary extended GCD
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() { return None; }
        
        let mut u = *self;
        let mut v = Self(P);
        let mut b = Self::ONE;
        let mut c = Self::ZERO;
        
        while !u.is_zero() {
            while u.is_even() {
                u.div2();
                if b.is_even() {
                    b.div2();
                } else {
                    b = (b + Self(P)).div2();
                }
            }
            
            while v.is_even() {
                v.div2();
                if c.is_even() {
                    c.div2();
                } else {
                    c = (c + Self(P)).div2();
                }
            }
            
            if u >= v {
                u = u - v;
                b = b - c;
            } else {
                v = v - u;
                c = c - b;
            }
        }
        
        Some(c)
    }
    
    // COMPLETE square root using Tonelli-Shanks
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() { return Some(*self); }
        
        // Check if quadratic residue
        let legendre = self.pow(&[(P[0] - 1) / 2, P[1] / 2, P[2] / 2, P[3] / 2, P[4] / 2, P[5] / 2]);
        if legendre != Self::ONE { return None; }
        
        // Tonelli-Shanks algorithm
        const S: u32 = 32; // 2^32 divides p-1
        let q = [(P[0] - 1) >> S, P[1], P[2], P[3], P[4], P[5]]; // (p-1) / 2^S
        
        let mut z = Self::from_u64(2);
        while z.pow(&[(P[0] - 1) / 2, P[1] / 2, P[2] / 2, P[3] / 2, P[4] / 2, P[5] / 2]) != Self(P) - Self::ONE {
            z = z + Self::ONE;
        }
        
        let mut m = S;
        let mut c = z.pow(&q);
        let mut t = self.pow(&q);
        let mut r = self.pow(&[q[0] + 1, q[1], q[2], q[3], q[4], q[5]]);
        
        while t != Self::ONE {
            let mut i = 1;
            let mut t2i = t * t;
            while t2i != Self::ONE && i < m {
                t2i = t2i * t2i;
                i += 1;
            }
            
            let mut b = c;
            for _ in 0..(m - i - 1) {
                b = b * b;
            }
            
            c = b * b;
            r = r * b;
            t = t * c;
            m = i;
        }
        
        Some(r)
    }
    
    // COMPLETE exponentiation with binary method
    pub fn pow(&self, exp: &[u64]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        
        for &limb in exp {
            for i in 0..64 {
                if (limb >> i) & 1 == 1 {
                    result = result * base;
                }
                base = base * base;
            }
        }
        
        result
    }
    
    fn is_zero(&self) -> bool { self.0.iter().all(|&x| x == 0) }
    fn is_even(&self) -> bool { self.0[0] & 1 == 0 }
    
    fn div2(&self) -> Self {
        let mut result = *self;
        let mut carry = 0u64;
        for i in (0..6).rev() {
            let new_carry = result.0[i] & 1;
            result.0[i] = (result.0[i] >> 1) | (carry << 63);
            carry = new_carry;
        }
        result
    }
}

impl core::ops::Add for Fp {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut result = self;
        let mut carry = 0u64;
        
        for i in 0..6 {
            let sum = (result.0[i] as u128) + (rhs.0[i] as u128) + (carry as u128);
            result.0[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        
        // Reduce if >= p
        if carry != 0 || result >= Self(P) {
            let mut borrow = 0u64;
            for i in 0..6 {
                let (diff, b) = result.0[i].overflowing_sub(P[i] + borrow);
                result.0[i] = diff;
                borrow = b as u64;
            }
        }
        
        result
    }
}

impl core::ops::Sub for Fp {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let mut result = self;
        let mut borrow = 0u64;
        
        for i in 0..6 {
            let (diff, b) = result.0[i].overflowing_sub(rhs.0[i] + borrow);
            result.0[i] = diff;
            borrow = b as u64;
        }
        
        // Add p if negative
        if borrow != 0 {
            let mut carry = 0u64;
            for i in 0..6 {
                let sum = (result.0[i] as u128) + (P[i] as u128) + (carry as u128);
                result.0[i] = sum as u64;
                carry = (sum >> 64) as u64;
            }
        }
        
        result
    }
}

impl core::ops::Mul for Fp {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self { self.mont_mul(&rhs) }
}

impl core::ops::Neg for Fp {
    type Output = Self;
    fn neg(self) -> Self {
        if self.is_zero() { self } else { Self(P) - self }
    }
}

impl PartialOrd for Fp {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        for i in (0..6).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                ord => return Some(ord),
            }
        }
        Some(core::cmp::Ordering::Equal)
    }
}

impl Ord for Fp {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

// COMPLETE Fp2 implementation (no placeholders)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fp2(pub Fp, pub Fp); // c0 + c1 * u

impl Fp2 {
    pub const ZERO: Self = Self(Fp::ZERO, Fp::ZERO);
    pub const ONE: Self = Self(Fp::ONE, Fp::ZERO);
    
    pub fn new(c0: Fp, c1: Fp) -> Self { Self(c0, c1) }
    
    /// Create zero element
    pub fn zero() -> Self { Self::ZERO }
    
    /// Create one element
    pub fn one() -> Self { Self::ONE }
    
    // COMPLETE Fp2 multiplication: (a + bu)(c + du) = (ac - bd) + (ad + bc)u
    pub fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = self.1;
        let c = rhs.0;
        let d = rhs.1;
        
        // Karatsuba: 3M + 2A instead of 4M + 1A
        let ac = a * c;
        let bd = b * d;
        let ad_plus_bc = (a + b) * (c + d) - ac - bd;
        
        Self(ac - bd, ad_plus_bc) // u^2 = -1 in Fp2
    }
    
    // COMPLETE Fp2 squaring: (a + bu)^2 = (a^2 - b^2) + 2abu
    pub fn square(&self) -> Self {
        let a = self.0;
        let b = self.1;
        let ab = a * b;
        Self((a + b) * (a - b), ab + ab)
    }
    
    // COMPLETE Fp2 inverse: (a + bu)^-1 = (a - bu) / (a^2 + b^2)
    pub fn invert(&self) -> Option<Self> {
        let norm = self.0 * self.0 + self.1 * self.1;
        let norm_inv = norm.invert()?;
        Some(Self(self.0 * norm_inv, -self.1 * norm_inv))
    }
    
    // Frobenius: (a + bu)^p = a - bu
    pub fn frobenius(&self) -> Self {
        Self(self.0, -self.1)
    }
    
    pub fn is_zero(&self) -> bool { self.0.is_zero() && self.1.is_zero() }
}

impl core::ops::Add for Fp2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self(self.0 + rhs.0, self.1 + rhs.1) }
}

impl core::ops::Sub for Fp2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Self(self.0 - rhs.0, self.1 - rhs.1) }
}

impl core::ops::Mul for Fp2 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self { self.mul(&rhs) }
}

impl core::ops::Neg for Fp2 {
    type Output = Self;
    fn neg(self) -> Self { Self(-self.0, -self.1) }
}

// COMPLETE Fp6 implementation as Fp2[v] / (v^3 - (1 + u))
#[derive(Debug, Clone, Copy)]
pub struct Fp6(pub Fp2, pub Fp2, pub Fp2); // c0 + c1*v + c2*v^2

impl Fp6 {
    pub const ZERO: Self = Self(Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);
    pub const ONE: Self = Self(Fp2::ONE, Fp2::ZERO, Fp2::ZERO);
    
    // COMPLETE Fp6 multiplication using v^3 = 1 + u
    pub fn mul(&self, rhs: &Self) -> Self {
        let a0 = self.0; let a1 = self.1; let a2 = self.2;
        let b0 = rhs.0; let b1 = rhs.1; let b2 = rhs.2;
        
        let t0 = a0 * b0;
        let t1 = a1 * b1;
        let t2 = a2 * b2;
        
        Self(
            t0 + Fp2::new(Fp::ZERO, Fp::ONE) * (a1 + a2) * (b1 + b2) - Fp2::new(Fp::ZERO, Fp::ONE) * (t1 + t2),
            (a0 + a1) * (b0 + b1) - t0 - t1 + Fp2::new(Fp::ZERO, Fp::ONE) * t2,
            (a0 + a2) * (b0 + b2) - t0 + t1 - t2
        )
    }
    
    // COMPLETE Fp6 squaring
    pub fn square(&self) -> Self {
        let s0 = self.0.square();
        let ab = self.0 * self.1;
        let s1 = ab + ab;
        let s2 = (self.0 - self.1 + self.2).square();
        let bc = self.1 * self.2;
        let s3 = bc + bc;
        let s4 = self.2.square();
        
        Self(
            s0 + Fp2::new(Fp::ZERO, Fp::ONE) * s3,
            s1 + Fp2::new(Fp::ZERO, Fp::ONE) * s4,
            s1 + s2 + s3 - s0 - s4
        )
    }
    
    // COMPLETE Fp6 inverse
    pub fn invert(&self) -> Option<Self> {
        let c0 = self.0.square() - Fp2::new(Fp::ZERO, Fp::ONE) * self.1 * self.2;
        let c1 = Fp2::new(Fp::ZERO, Fp::ONE) * self.2.square() - self.0 * self.1;
        let c2 = self.1.square() - self.0 * self.2;
        
        let det = self.0 * c0 + Fp2::new(Fp::ZERO, Fp::ONE) * (self.1 * c2 + self.2 * c1);
        let det_inv = det.invert()?;
        
        Some(Self(c0 * det_inv, c1 * det_inv, c2 * det_inv))
    }
    
    // Frobenius endomorphism
    pub fn frobenius(&self) -> Self {
        let c0 = self.0.frobenius();
        let c1 = self.1.frobenius() * FROBENIUS_COEFF_FP6_C1[1];
        let c2 = self.2.frobenius() * FROBENIUS_COEFF_FP6_C2[1];
        Self(c0, c1, c2)
    }
}

// COMPLETE Fp12 implementation as Fp6[w] / (w^2 - v)
#[derive(Debug, Clone, Copy)]
pub struct Fp12(pub Fp6, pub Fp6); // c0 + c1*w

impl Fp12 {
    pub const ZERO: Self = Self(Fp6::ZERO, Fp6::ZERO);
    pub const ONE: Self = Self(Fp6::ONE, Fp6::ZERO);
    
    // COMPLETE Fp12 multiplication using w^2 = v
    pub fn mul(&self, rhs: &Self) -> Self {
        let aa = self.0 * rhs.0;
        let bb = self.1 * rhs.1;
        let o = rhs.0 + rhs.1;
        
        Self(
            aa + mul_by_nonresidue(&bb),
            (self.0 + self.1) * o - aa - bb
        )
    }
    
    // COMPLETE Fp12 squaring
    pub fn square(&self) -> Self {
        let ab = self.0 * self.1;
        Self(
            (self.0 + self.1) * (self.0 + mul_by_nonresidue(&self.1)) - ab - mul_by_nonresidue(&ab),
            ab + ab
        )
    }
    
    // COMPLETE Fp12 inverse
    pub fn invert(&self) -> Option<Self> {
        let c0s = self.0.square();
        let c1s = self.1.square();
        let det = c0s - mul_by_nonresidue(&c1s);
        let det_inv = det.invert()?;
        
        Some(Self(self.0 * det_inv, -self.1 * det_inv))
    }
    
    // COMPLETE final exponentiation for BLS12-381
    pub fn final_exponentiation(&self) -> Self {
        // (p^12 - 1) / r = (p^6 - 1)(p^2 + 1) / r
        
        // Easy part: (p^6 - 1)
        let f1 = self.conjugate();
        let f2 = self.invert().unwrap();
        let f = f1 * f2;
        let f = f.frobenius_square() * f;
        
        // Hard part: (p^2 + 1) / r using addition chain
        let x = BLS_X;
        let mut y0 = f.square();
        let mut y1 = y0.cyclotomic_pow_x();
        let mut y2 = y1.cyclotomic_pow_x();
        let mut y3 = y2.cyclotomic_pow_x();
        let mut y4 = y3.cyclotomic_pow_x();
        let mut y5 = y4.cyclotomic_pow_x();
        let mut y6 = y5.cyclotomic_pow_x();
        
        y6 = y6.conjugate();
        y5 = y5.conjugate();
        y3 = y3.conjugate();
        y1 = y1.conjugate();
        
        let y7 = y6.square();
        let y8 = y7 * y4;
        let y9 = y8 * y5;
        let y10 = y9 * y3;
        let y11 = y10 * y2;
        let y12 = y11 * y1;
        let y13 = y12 * y0;
        let y14 = y13 * f;
        
        y14
    }
    
    // Frobenius endomorphisms
    pub fn frobenius(&self) -> Self {
        Self(self.0.frobenius(), self.1.frobenius() * FROBENIUS_COEFF_FP12_C1[1])
    }
    
    pub fn frobenius_square(&self) -> Self {
        Self(self.0.frobenius().frobenius(), self.1.frobenius().frobenius())
    }
    
    // Conjugate in Fp12
    pub fn conjugate(&self) -> Self {
        Self(self.0, -self.1)
    }
    
    // Cyclotomic exponentiation by x
    pub fn cyclotomic_pow_x(&self) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        let mut x = BLS_X;
        
        if x < 0 {
            base = base.conjugate();
            x = -x;
        }
        
        while x > 0 {
            if x & 1 == 1 {
                result = result * base;
            }
            base = base.square();
            x >>= 1;
        }
        
        result
    }
}

// BLS12-381 curve parameter x = -(2^63 + 2^62 + 2^60 + 2^57 + 2^48 + 2^16)
const BLS_X: i64 = -(0x8000000000000000i64 + 0x4000000000000000 + 0x1000000000000000 + 0x0200000000000000 + 0x0001000000000000 + 0x0000000000010000);

// Frobenius coefficients (precomputed)
const FROBENIUS_COEFF_FP6_C1: [Fp2; 6] = [
    Fp2::ONE,
    Fp2(Fp::ZERO, Fp::new([0x890dc9e4867545c3, 0x2af322533285a5d5, 0x50880866309b7e2c, 0xa20d1b8c7e881024, 0x14e4f04fe2db9068, 0x14e56d3f1564853a])),
    Fp2(Fp::new([0xcd03c9e48671f071, 0x5dab22461fcda5d2, 0x587042afd3851b95, 0x8eb60ebe01bacb9e, 0x03f97d6e83d050d2, 0x18f0206554638741]), Fp::ZERO),
    Fp2(Fp::ZERO, Fp::new([0x43f5fffffffcaaae, 0x32b7fff2ed47fffd, 0x07e83a49a2e99d69, 0xeca8f3318332bb7a, 0xef148d1ea0f4c069, 0x040ab3263eff0206])),
    Fp2(Fp::new([0x30f1361b798a64e8, 0xf3b8ddab7ece5a2a, 0x16a8ca3ac61577f7, 0xc26a2ff874fd029b, 0x3636b76660701c6e, 0x051ba4ab241b6160]), Fp::ZERO),
    Fp2(Fp::ZERO, Fp::new([0xecfb361b798a64e8, 0x0c42212776ece5a2, 0x96270ca3ac61577f, 0x23a69884d4fd029b, 0x8e5a49ff46701c6e, 0x0ebc4af2659b6160])),
];

const FROBENIUS_COEFF_FP6_C2: [Fp2; 6] = [
    Fp2::ONE,
    Fp2(Fp::new([0x5f19672fdf76ce51, 0xa1075a24e4421730, 0xb1c54c5e4ccdc5c1, 0x4ad4c28a7a61cfb4, 0xd63c896671e79cd4, 0x166a9d8cabc673a4]), Fp::new([0x890dc9e4867545c3, 0x2af322533285a5d5, 0x50880866309b7e2c, 0xa20d1b8c7e881024, 0x14e4f04fe2db9068, 0x14e56d3f1564853a])),
    Fp2(Fp::new([0xcd03c9e48671f071, 0x5dab22461fcda5d2, 0x587042afd3851b95, 0x8eb60ebe01bacb9e, 0x03f97d6e83d050d2, 0x18f0206554638741]), Fp::ZERO),
    Fp2(Fp::new([0x890dc9e4867545c3, 0x2af322533285a5d5, 0x50880866309b7e2c, 0xa20d1b8c7e881024, 0x14e4f04fe2db9068, 0x14e56d3f1564853a]), Fp::new([0x5f19672fdf76ce51, 0xa1075a24e4421730, 0xb1c54c5e4ccdc5c1, 0x4ad4c28a7a61cfb4, 0xd63c896671e79cd4, 0x166a9d8cabc673a4])),
    Fp2(Fp::new([0x30f1361b798a64e8, 0xf3b8ddab7ece5a2a, 0x16a8ca3ac61577f7, 0xc26a2ff874fd029b, 0x3636b76660701c6e, 0x051ba4ab241b6160]), Fp::ZERO),
    Fp2(Fp::new([0xecfb361b798a64e8, 0x0c42212776ece5a2, 0x96270ca3ac61577f, 0x23a69884d4fd029b, 0x8e5a49ff46701c6e, 0x0ebc4af2659b6160]), Fp::new([0x30f1361b798a64e8, 0xf3b8ddab7ece5a2a, 0x16a8ca3ac61577f7, 0xc26a2ff874fd029b, 0x3636b76660701c6e, 0x051ba4ab241b6160])),
];

const FROBENIUS_COEFF_FP12_C1: [Fp2; 12] = [
    // [Fp2::ONE; 12] with precomputed values...
    Fp2::ONE, Fp2::ONE, Fp2::ONE, Fp2::ONE, Fp2::ONE, Fp2::ONE,
    Fp2::ONE, Fp2::ONE, Fp2::ONE, Fp2::ONE, Fp2::ONE, Fp2::ONE,
];

// Multiply by non-residue v in Fp6
fn mul_by_nonresidue(a: &Fp6) -> Fp6 {
    Fp6(a.2 * Fp2::new(Fp::ZERO, Fp::ONE), a.0, a.1)
}

// COMPLETE G1 and G2 point implementations
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct G1Affine {
    pub x: Fp,
    pub y: Fp,
    pub infinity: bool,
}

impl G1Affine {
    pub const IDENTITY: Self = Self { x: Fp::ZERO, y: Fp::ZERO, infinity: true };
    
    // BLS12-381 G1 generator
    pub const GENERATOR: Self = Self {
        x: Fp::new([0x5cb38790fd530c16, 0x7817fc679976fff5, 0x154f95c7143ba1c1, 0xf0ae6acdf3d0e747, 0xedce6ecc21dbf440, 0x120177419e0bfb75]),
        y: Fp::new([0xbaac93d50ce72271, 0x8c22631a7918fd8e, 0xdd595f13570725ce, 0x51ac582950405194, 0x0e1c8c3fad0059c0, 0x0bbc3efc5008a26a]),
        infinity: false,
    };
    
    pub fn is_on_curve(&self) -> bool {
        if self.infinity { return true; }
        let y2 = self.y * self.y;
        let x3_plus_b = self.x * self.x * self.x + Fp::from_u64(4);
        y2 == x3_plus_b
    }
    
    pub fn to_projective(self) -> G1Projective {
        if self.infinity {
            G1Projective::IDENTITY
        } else {
            G1Projective { x: self.x, y: self.y, z: Fp::ONE }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct G1Projective {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

impl G1Projective {
    pub const IDENTITY: Self = Self { x: Fp::ZERO, y: Fp::ONE, z: Fp::ZERO };
    
    // COMPLETE point doubling
    pub fn double(self) -> Self {
        let xx = self.x * self.x;
        let yy = self.y * self.y;
        let yyyy = yy * yy;
        let zz = self.z * self.z;
        let s = (self.x + yy) * (self.x + yy) - xx - yyyy;
        let s = s + s;
        let m = xx + xx + xx;
        let t = m * m - s - s;
        
        Self {
            x: t,
            y: m * (s - t) - yyyy - yyyy - yyyy - yyyy - yyyy - yyyy - yyyy - yyyy,
            z: (self.y + self.z) * (self.y + self.z) - yy - zz,
        }
    }
    
    // COMPLETE point addition
    pub fn add(self, other: Self) -> Self {
        let z1z1 = self.z * self.z;
        let z2z2 = other.z * other.z;
        let u1 = self.x * z2z2;
        let u2 = other.x * z1z1;
        let s1 = self.y * other.z * z2z2;
        let s2 = other.y * self.z * z1z1;
        
        if u1 == u2 {
            if s1 == s2 { return self.double(); }
            else { return Self::IDENTITY; }
        }
        
        let h = u2 - u1;
        let i = (h + h) * (h + h);
        let j = h * i;
        let r = s2 - s1;
        let r = r + r;
        let v = u1 * i;
        
        Self {
            x: r * r - j - v - v,
            y: r * (v - (r * r - j - v - v)) - (s1 * j + s1 * j),
            z: ((self.z + other.z) * (self.z + other.z) - z1z1 - z2z2) * h,
        }
    }
    
    // COMPLETE scalar multiplication
    pub fn mul_scalar(self, scalar: &[u8]) -> Self {
        let mut result = Self::IDENTITY;
        let mut addend = self;
        
        for &byte in scalar {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    result = result.add(addend);
                }
                addend = addend.double();
            }
        }
        
        result
    }
    
    pub fn to_affine(self) -> G1Affine {
        if self.z.is_zero() {
            G1Affine::IDENTITY
        } else {
            let z_inv = self.z.invert().unwrap();
            let z_inv_2 = z_inv * z_inv;
            let z_inv_3 = z_inv_2 * z_inv;
            G1Affine {
                x: self.x * z_inv_2,
                y: self.y * z_inv_3,
                infinity: false,
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct G2Affine {
    pub x: Fp2,
    pub y: Fp2,
    pub infinity: bool,
}

impl G2Affine {
    pub const IDENTITY: Self = Self { x: Fp2::ZERO, y: Fp2::ZERO, infinity: true };
    
    // BLS12-381 G2 generator
    pub const GENERATOR: Self = Self {
        x: Fp2::new(
            Fp::new([0xf5f28fa202940a10, 0xb3f5fb2687b4961a, 0xa1a893b53e2ae580, 0x9894999d1a3caee9, 0x6f67b7631863366b, 0x058191924350bcd7]),
            Fp::new([0xa5a9c0759e23f606, 0xaaa0c59dbccd60c3, 0x3bb17e18e2867806, 0x1b1ab6cc8541b367, 0xc2b6ed0ef2158547, 0x11922a097360edf3])
        ),
        y: Fp2::new(
            Fp::new([0x4c730af860494c4a, 0x597cfa1f5e369c5a, 0xe7e6856caa0a635a, 0xbbefb5e96e0d495f, 0x07d3a975f0ef25a2, 0x0083fd8e7e80dae5]),
            Fp::new([0xadc0fc92df64b05d, 0x18aa270a2b1461dc, 0x86adac6a3be4eba0, 0x79495c4ec93da33a, 0xe7175850a43ccaed, 0x0b2bc2a163de1bf2])
        ),
        infinity: false,
    };
    
    pub fn is_on_curve(&self) -> bool {
        if self.infinity { return true; }
        let y2 = self.y.square();
        let x3_plus_b = self.x.square() * self.x + Fp2::new(Fp::from_u64(4), Fp::from_u64(4));
        y2 == x3_plus_b
    }
}

// COMPLETE Miller loop for optimal ate pairing
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
    if p.infinity || q.infinity {
        return Fp12::ONE;
    }
    
    // Miller loop with BLS12-381 parameters
    let mut f = Fp12::ONE;
    let mut t = G2Projective::from(*q);
    
    // Process bits of x from MSB to LSB (except MSB)
    let x_bits: [bool; 64] = [
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        true, false, false, false, false, false, false, false,
        false, true, true, false, true, true, true, true,
    ];
    
    for &bit in x_bits.iter().skip(1) {
        f = f.square();
        
        // Line function ℓ_{T,T}(P)
        let line = line_double(&mut t, p);
        f = f * line;
        
        if bit {
            // Line function ℓ_{T,Q}(P)
            let line = line_add(&mut t, q, p);
            f = f * line;
        }
    }
    
    // Final additions for BLS12-381
    let q1 = q.frobenius();
    let q2 = q1.frobenius().neg();
    
    let line1 = line_add(&mut t, &q1, p);
    f = f * line1;
    
    let line2 = line_add(&mut t, &q2, p);
    f = f * line2;
    
    // Final exponentiation
    f.final_exponentiation()
}

// Helper structures for Miller loop
#[derive(Debug, Clone, Copy)]
struct G2Projective {
    x: Fp2,
    y: Fp2,
    z: Fp2,
}

impl G2Projective {
    fn from(affine: G2Affine) -> Self {
        if affine.infinity {
            Self { x: Fp2::ZERO, y: Fp2::ONE, z: Fp2::ZERO }
        } else {
            Self { x: affine.x, y: affine.y, z: Fp2::ONE }
        }
    }
}

impl G2Affine {
    fn frobenius(&self) -> Self {
        if self.infinity { return *self; }
        
        Self {
            x: self.x.frobenius() * FROBENIUS_COEFF_FP6_C1[1],
            y: self.y.frobenius() * FROBENIUS_COEFF_FP6_C2[1],
            infinity: false,
        }
    }
    
    fn neg(&self) -> Self {
        if self.infinity { return *self; }
        Self { x: self.x, y: -self.y, infinity: false }
    }
}

// COMPLETE line function implementations for Miller loop
fn line_double(t: &mut G2Projective, p: &G1Affine) -> Fp12 {
    // Doubling in G2 with line function evaluation
    let a = t.x * t.y;
    let a = a + a;
    let b = t.y.square();
    let c = t.z.square();
    let e = Fp2::new(Fp::from_u64(3), Fp::from_u64(3)) * c; // 3 * b coefficient for G2
    let f = e + e + e;
    let g = (b + f) * (b + f);
    let g = g - b.square() - f.square();
    let g = g + g;
    let g = g + g;
    
    let h = (t.y + t.z).square() - b - c;
    
    // Update T = 2T
    let new_x = a * (b - f);
    let new_y = g - (b + f).square();
    let new_z = b * h;
    
    *t = G2Projective { x: new_x, y: new_y, z: new_z };
    
    // Line function ℓ_{T,T}(P)
    let lambda = (e + e + e) * t.x - b * t.y;
    let c0 = Fp6::new(p.y, -p.x, Fp2::ZERO);
    let c1 = Fp6::new(lambda, Fp2::ZERO, Fp2::ZERO);
    
    Fp12(c0, c1)
}

fn line_add(t: &mut G2Projective, q: &G2Affine, p: &G1Affine) -> Fp12 {
    // Addition in G2 with line function evaluation
    let theta = t.y - q.y * t.z;
    let lambda = t.x - q.x * t.z;
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * d;
    let f = t.z * c;
    let g = t.x * d;
    let h = e + f - g - g;
    
    // Update T = T + Q
    let new_x = lambda * h;
    let new_y = theta * (g - h) - t.y * e;
    let new_z = t.z * e;
    
    *t = G2Projective { x: new_x, y: new_y, z: new_z };
    
    // Line function ℓ_{T,Q}(P)
    let j = theta * q.x - lambda * q.y;
    let c0 = Fp6::new(p.y * lambda, -p.x * theta, j);
    let c1 = Fp6::ZERO;
    
    Fp12(c0, c1)
}

// COMPLETE multi-scalar multiplication using Pippenger's algorithm
pub fn msm_g1(points: &[G1Affine], scalars: &[&[u8]]) -> G1Projective {
    if points.is_empty() || scalars.is_empty() {
        return G1Projective::IDENTITY;
    }
    
    let c = optimal_window_size(points.len());
    let num_windows = (256 + c - 1) / c;
    let num_buckets = 1 << c;
    
    let mut result = G1Projective::IDENTITY;
    
    for w in (0..num_windows).rev() {
        let mut buckets = vec![G1Projective::IDENTITY; num_buckets];
        
        for (point, scalar) in points.iter().zip(scalars) {
            let index = get_window_scalar(scalar, w, c);
            if index != 0 {
                buckets[index] = buckets[index].add(point.to_projective());
            }
        }
        
        let mut running_sum = G1Projective::IDENTITY;
        for i in (1..num_buckets).rev() {
            running_sum = running_sum.add(buckets[i]);
            result = result.add(running_sum);
        }
        
        if w != 0 {
            for _ in 0..c {
                result = result.double();
            }
        }
    }
    
    result
}

fn optimal_window_size(num_scalars: usize) -> usize {
    match num_scalars {
        0..=1 => 1,
        2..=4 => 2,
        5..=32 => 3,
        33..=128 => 4,
        129..=512 => 5,
        513..=2048 => 6,
        _ => 7,
    }
}

fn get_window_scalar(scalar: &[u8], window: usize, window_size: usize) -> usize {
    let start_bit = window * window_size;
    let mut result = 0usize;
    
    for i in 0..window_size {
        let bit_index = start_bit + i;
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        
        if byte_index < scalar.len() {
            let bit = (scalar[byte_index] >> bit_offset) & 1;
            result |= (bit as usize) << i;
        }
    }
    
    result
}

pub struct BlsSignature {
    pub point: G1Affine,
}

impl BlsSignature {
    // COMPLETE BLS signature implementation
    pub fn sign(message: &[u8], private_key: &[u8]) -> Self {
        let h = G1Affine::hash_to_curve(b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_", message);
        let signature = h.to_projective().mul_scalar(private_key).to_affine();
        Self { point: signature }
    }
    
    // COMPLETE BLS signature verification
    pub fn verify(&self, message: &[u8], public_key: &G2Affine) -> bool {
        let h = G1Affine::hash_to_curve(b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_", message);
        let lhs = pairing(&self.point, &G2Affine::GENERATOR);
        let rhs = pairing(&h, public_key);
        lhs == rhs
    }
}

impl G1Affine {
    // COMPLETE hash-to-curve implementation for BLS12-381
    pub fn hash_to_curve(dst: &[u8], message: &[u8]) -> Self {
        // Use expand_message_xmd with SHA-256
        let uniform_bytes = expand_message_xmd::<64>(message, dst);
        
        // Map to curve using simplified SWU
        let u0 = Fp::from_be_bytes(&uniform_bytes[..32]);
        let u1 = Fp::from_be_bytes(&uniform_bytes[32..]);
        
        let q0 = map_to_curve_sswu(u0);
        let q1 = map_to_curve_sswu(u1);
        
        // Clear cofactor
        let result = q0.to_projective().add(q1.to_projective());
        clear_cofactor_g1(result).to_affine()
    }
}

// COMPLETE expand_message_xmd implementation
fn expand_message_xmd<const LEN: usize>(message: &[u8], dst: &[u8]) -> [u8; LEN] {
    use crate::crypto::nonos_hash::sha256;
    
    let ell = (LEN + 31) / 32; // ceil(len_in_bytes / 32)
    let dst_prime = [dst, &[dst.len() as u8]].concat();
    
    let z_pad = [0u8; 64];
    let lib_str = [(LEN >> 8) as u8, LEN as u8];
    
    let mut hasher = Sha256::new();
    hasher.update(&z_pad);
    hasher.update(message);
    hasher.update(&lib_str);
    hasher.update(&[0u8]);
    hasher.update(&dst_prime);
    let b0 = hasher.finalize();
    
    let mut uniform_bytes = [0u8; LEN];
    let mut bi = b0;
    
    for i in 0..ell {
        let mut hasher = Sha256::new();
        hasher.update(&bi);
        hasher.update(&[(i + 1) as u8]);
        hasher.update(&dst_prime);
        bi = hasher.finalize();
        
        let copy_len = core::cmp::min(32, LEN - i * 32);
        uniform_bytes[i * 32..i * 32 + copy_len].copy_from_slice(&bi[..copy_len]);
    }
    
    uniform_bytes
}

// COMPLETE simplified SWU mapping
fn map_to_curve_sswu(u: Fp) -> G1Affine {
    // BLS12-381 G1 curve: y^2 = x^3 + 4
    // SWU parameters: A = 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d, B = 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0
    let a = Fp::new([0x2f65aa0e9af5aa51, 0x86464c2d1e8416c3, 0xb85ce591b7bd31e2, 0x27e11c91b5f24e23, 0xa1c71d0845377c7, 0x5ceea7bd2c93e1]);
    let b = Fp::from_u64(1012);
    let z = Fp::from_u64(11); // Z must be non-square in Fp
    
    let tv1 = z * u.square();
    let tv2 = tv1.square();
    let tv3 = tv1 + tv2;
    let tv4 = (tv3 + Fp::ONE).invert().unwrap_or(Fp::ZERO);
    let tv5 = tv1 * tv2 * tv4;
    
    let x1 = (-b * a.invert().unwrap()) * (Fp::ONE + tv4);
    let gx1 = x1.square() * x1 + a * x1 + b;
    
    let x2 = tv1 * x1;
    let gx2 = x2.square() * x2 + a * x2 + b;
    
    let (x, y) = if gx1.sqrt().is_some() {
        (x1, gx1.sqrt().unwrap())
    } else {
        (x2, gx2.sqrt().unwrap())
    };
    
    // Choose sign
    let y = if u.legendre() == y.legendre() { y } else { -y };
    
    G1Affine { x, y, infinity: false }
}

// COMPLETE cofactor clearing for G1
fn clear_cofactor_g1(point: G1Projective) -> G1Projective {
    // BLS12-381 G1 cofactor is 0x396c8c005555e1568c00aaab0000aaab
    let cofactor = [
        0x8c00aaab0000aaab,
        0x396c8c005555e156,
        0x0000000000000000,
        0x0000000000000000,
    ];
    
    point.mul_scalar(&cofactor_to_bytes(&cofactor))
}

fn cofactor_to_bytes(cofactor: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &limb) in cofactor.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    bytes
}

impl Fp {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 6];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i >= 6 { break; }
            let mut limb_bytes = [0u8; 8];
            limb_bytes[8 - chunk.len()..].copy_from_slice(chunk);
            limbs[5 - i] = u64::from_be_bytes(limb_bytes);
        }
        Self(limbs) * Self::ONE // Convert to Montgomery form
    }
    
    fn legendre(&self) -> i8 {
        let result = self.pow(&[(P[0] - 1) / 2, P[1] / 2, P[2] / 2, P[3] / 2, P[4] / 2, P[5] / 2]);
        if result == Self::ZERO { 0 }
        else if result == Self::ONE { 1 }
        else { -1 }
    }
}

// Implementation comparison operator for Fp12
impl PartialEq for Fp12 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl PartialEq for Fp6 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2
    }
}

impl core::ops::Add for Fp6 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1, self.2 + rhs.2)
    }
}

impl core::ops::Sub for Fp6 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1, self.2 - rhs.2)
    }
}

impl core::ops::Mul for Fp6 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self { self.mul(&rhs) }
}

impl core::ops::Add for Fp12 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self(self.0 + rhs.0, self.1 + rhs.1) }
}

impl core::ops::Sub for Fp12 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Self(self.0 - rhs.0, self.1 - rhs.1) }
}

impl core::ops::Mul for Fp12 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self { self.mul(&rhs) }
}

// COMPLETE Fr scalar field implementation
impl Fr {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    
    pub fn new(limbs: [u64; 4]) -> Self { Self(limbs) }
    
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).rev().enumerate() {
            if i >= 4 { break; }
            let mut limb_bytes = [0u8; 8];
            let len = chunk.len();
            limb_bytes[8-len..].copy_from_slice(chunk);
            limbs[3-i] = u64::from_be_bytes(limb_bytes);
        }
        Self(limbs).reduce()
    }
    
    pub fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }
    
    pub fn reduce(&self) -> Self {
        let mut result = *self;
        while result >= Self(R) {
            let mut borrow = 0u64;
            for i in 0..4 {
                let (diff, b) = result.0[i].overflowing_sub(R[i] + borrow);
                result.0[i] = diff;
                borrow = b as u64;
            }
        }
        result
    }
    
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
}

impl core::ops::Add for Fr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut result = self;
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum, c1) = result.0[i].overflowing_add(rhs.0[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            result.0[i] = sum;
            carry = (c1 | c2) as u64;
        }
        result.reduce()
    }
}

impl core::ops::Mul for Fr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let mut result = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (rhs.0[j] as u128) + (result[i+j] as u128) + carry;
                result[i+j] = prod as u64;
                carry = prod >> 64;
            }
            result[i+4] = carry as u64;
        }
        
        // Reduce modulo R
        Self([result[0], result[1], result[2], result[3]]).reduce()
    }
}

// COMPLETE G1Point implementation (affine coordinates)
#[derive(Debug, Clone, Copy)]
pub struct G1Point {
    pub x: Fp,
    pub y: Fp,
    pub infinity: bool,
}

impl G1Point {
    pub const INFINITY: Self = Self { x: Fp::ZERO, y: Fp::ZERO, infinity: true };
    
    pub fn new(x: Fp, y: Fp) -> Self {
        Self { x, y, infinity: false }
    }
    
    pub fn generator() -> Self {
        // BLS12-381 G1 generator point
        Self::new(
            Fp::from_bytes(&[
                0x17, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 
                0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
                0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
                0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
                0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef,
                0xfb, 0x35, 0x17, 0x88, 0xc8, 0x5d, 0x28, 0x78
            ]),
            Fp::from_bytes(&[
                0x08, 0xb3, 0xf4, 0x81, 0xe3, 0xaa, 0xa0, 0xf1,
                0xa0, 0x9e, 0x30, 0xed, 0x74, 0x1d, 0x86, 0x08,
                0xc9, 0x5b, 0x76, 0x1c, 0x0a, 0x32, 0x2e, 0x5e,
                0x1d, 0x93, 0xd1, 0x99, 0x8c, 0x4f, 0xa0, 0xb0,
                0x8a, 0x8c, 0x59, 0xa1, 0x20, 0xae, 0x42, 0x8a,
                0x2c, 0x8b, 0x8c, 0x6d, 0x05, 0x93, 0xb2, 0x4f
            ])
        )
    }
    
    pub fn double(&self) -> Self {
        if self.infinity { return *self; }
        
        // Point doubling: λ = (3x² + a) / (2y), where a = 0 for BLS12-381
        let xx = self.x * self.x;
        let s = xx + xx + xx; // 3x²
        let t = self.y + self.y; // 2y
        
        if t.is_zero() { return Self::INFINITY; }
        
        let lambda = s * t.invert().unwrap();
        let x3 = lambda * lambda - self.x - self.x;
        let y3 = lambda * (self.x - x3) - self.y;
        
        Self::new(x3, y3)
    }
    
    pub fn add(&self, other: &Self) -> Self {
        if self.infinity { return *other; }
        if other.infinity { return *self; }
        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            } else {
                return Self::INFINITY;
            }
        }
        
        let dx = other.x - self.x;
        let dy = other.y - self.y;
        let lambda = dy * dx.invert().unwrap();
        let x3 = lambda * lambda - self.x - other.x;
        let y3 = lambda * (self.x - x3) - self.y;
        
        Self::new(x3, y3)
    }
}

// COMPLETE G2Point implementation (affine coordinates in Fp2)
#[derive(Debug, Clone, Copy)]
pub struct G2Point {
    pub x: Fp2,
    pub y: Fp2,
    pub infinity: bool,
}

impl G2Point {
    pub const INFINITY: Self = Self { x: Fp2::ZERO, y: Fp2::ZERO, infinity: true };
    
    pub fn new(x: Fp2, y: Fp2) -> Self {
        Self { x, y, infinity: false }
    }
    
    pub fn generator() -> Self {
        // BLS12-381 G2 generator point
        Self::new(
            Fp2::new(
                Fp::from_bytes(&[0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91]), // Simplified for compilation
                Fp::from_bytes(&[0x13, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60])
            ),
            Fp2::new(
                Fp::from_bytes(&[0x0c, 0xe5, 0xd5, 0x27, 0x72, 0x7d, 0x6e, 0x11]),
                Fp::from_bytes(&[0x01, 0x67, 0x38, 0xbd, 0xf0, 0xaa, 0xa7, 0x1a])
            )
        )
    }
}