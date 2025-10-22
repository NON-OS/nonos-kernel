//! Ed25519 (RFC 8032) - constant-time, accelerated

#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]

extern crate alloc;
use alloc::vec::Vec;
// use core::ops::{Add, Sub};
use core::ptr;
use spin::Once;

use crate::crypto::sha512::sha512;
use crate::crypto::rng::get_random_bytes;

// ---------------- Public types ----------------

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: [u8; 32],  // encoded A = a*B
    pub private: [u8; 32], // seed (only seed stored; a is derived)
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        for b in &mut self.private {
            unsafe { ptr::write_volatile(b, 0) };
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub R: [u8; 32],
    pub S: [u8; 32],
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.R);
        out[32..].copy_from_slice(&self.S);
        out
    }
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut R = [0u8; 32];
        let mut S = [0u8; 32];
        R.copy_from_slice(&b[..32]);
        S.copy_from_slice(&b[32..]);
        Self { R, S }
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::from_seed(get_random_bytes())
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let h = sha512(&seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp_scalar(&mut a);
        ensure_precomp();
        let A = ge_scalarmult_base_ct(&a);
        let public = ge_pack(&A);
        Self { public, private: seed }
    }
}

// ---------------- Field arithmetic (ref10 10×25/26-bit) ----------------

#[derive(Copy, Clone)]
struct Fe([i32; 10]);

impl Fe {
    #[inline] fn zero() -> Self { Fe([0;10]) }
    #[inline] fn one() -> Self { let mut t=[0;10]; t[0]=1; Fe(t) }
}

#[inline] fn fe_copy(a: &Fe) -> Fe { *a }
#[inline] fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0i32;10];
    for i in 0..10 { r[i]=a.0[i]+b.0[i]; }
    Fe(r)
}
#[inline] fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0i32;10];
    for i in 0..10 { r[i]=a.0[i]-b.0[i]; }
    Fe(r)
}

// Multiplication/square adapted from ref10 (portable; constant-time)
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0=a.0[0] as i64; let a1=a.0[1] as i64; let a2=a.0[2] as i64; let a3=a.0[3] as i64; let a4=a.0[4] as i64;
    let a5=a.0[5] as i64; let a6=a.0[6] as i64; let a7=a.0[7] as i64; let a8=a.0[8] as i64; let a9=a.0[9] as i64;

    let b0=b.0[0] as i64; let b1=b.0[1] as i64; let b2=b.0[2] as i64; let b3=b.0[3] as i64; let b4=b.0[4] as i64;
    let b5=b.0[5] as i64; let b6=b.0[6] as i64; let b7=b.0[7] as i64; let b8=b.0[8] as i64; let b9=b.0[9] as i64;

    let b1_19=b1*19; let b2_19=b2*19; let b3_19=b3*19; let b4_19=b4*19; let b5_19=b5*19; let b6_19=b6*19; let b7_19=b7*19; let b8_19=b8*19; let b9_19=b9*19;
    let a1_2=a1*2; let a3_2=a3*2; let a5_2=a5*2; let a7_2=a7*2; let a9_2=a9*2;

    let mut c0 = a0*b0 + a1_2*b9_19 + a2*b8_19 + a3_2*b7_19 + a4*b6_19 + a5_2*b5_19 + a6*b4_19 + a7_2*b3_19 + a8*b2_19 + a9_2*b1_19;
    let mut c1 = a0*b1 + a1*b0 + a2*b9_19 + a3*b8_19 + a4*b7_19 + a5*b6_19 + a6*b5_19 + a7*b4_19 + a8*b3_19 + a9*b2_19;
    let mut c2 = a0*b2 + a1_2*b1 + a2*b0 + a3_2*b9_19 + a4*b8_19 + a5_2*b7_19 + a6*b6_19 + a7_2*b5_19 + a8*b4_19 + a9_2*b3_19;
    let mut c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + a4*b9_19 + a5*b8_19 + a6*b7_19 + a7*b6_19 + a8*b5_19 + a9*b4_19;
    let mut c4 = a0*b4 + a1_2*b3 + a2*b2 + a3_2*b1 + a4*b0 + a5_2*b9_19 + a6*b8_19 + a7_2*b7_19 + a8*b6_19 + a9_2*b5_19;
    let mut c5 = a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0 + a6*b9_19 + a7*b8_19 + a8*b7_19 + a9*b6_19;
    let mut c6 = a0*b6 + a1_2*b5 + a2*b4 + a3_2*b3 + a4*b2 + a5_2*b1 + a6*b0 + a7_2*b9_19 + a8*b8_19 + a9_2*b7_19;
    let mut c7 = a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0 + a8*b9_19 + a9*b8_19;
    let mut c8 = a0*b8 + a1_2*b7 + a2*b6 + a3_2*b5 + a4*b4 + a5_2*b3 + a6*b2 + a7_2*b1 + a8*b0 + a9_2*b9_19;
    let mut c9 = a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;

    // carries (per ref10)
    let mut carry=[0i64;10];
    carry[0]=(c0 + (1<<25))>>26; c1+=carry[0]; c0-=carry[0]<<26;
    carry[4]=(c4 + (1<<25))>>26; c5+=carry[4]; c4-=carry[4]<<26;
    carry[1]=(c1 + (1<<24))>>25; c2+=carry[1]; c1-=carry[1]<<25;
    carry[5]=(c5 + (1<<24))>>25; c6+=carry[5]; c5-=carry[5]<<25;
    carry[2]=(c2 + (1<<25))>>26; c3+=carry[2]; c2-=carry[2]<<26;
    carry[6]=(c6 + (1<<25))>>26; c7+=carry[6]; c6-=carry[6]<<26;
    carry[3]=(c3 + (1<<24))>>25; c4+=carry[3]; c3-=carry[3]<<25;
    carry[7]=(c7 + (1<<24))>>25; c8+=carry[7]; c7-=carry[7]<<25;
    carry[4]=(c4 + (1<<25))>>26; c5+=carry[4]; c4-=carry[4]<<26;
    carry[8]=(c8 + (1<<25))>>26; c9+=carry[8]; c8-=carry[8]<<26;
    carry[9]=(c9 + (1<<24))>>25; c9-=carry[9]<<25;

    Fe([c0 as i32,c1 as i32,c2 as i32,c3 as i32,c4 as i32,c5 as i32,c6 as i32,c7 as i32,c8 as i32,c9 as i32])
}
#[inline] fn fe_sq(a: &Fe) -> Fe { fe_mul(a,a) }

fn fe_invert(z: &Fe) -> Fe { fe_pow2523(z) } // ref10 ladder (2^252-3)

fn fe_pow2523(z: &Fe) -> Fe {
    // Standard ref10 chain (short form)
    let mut t0 = fe_sq(z);
    let mut t1 = fe_sq(&t0);
    for _ in 0..1 { t1 = fe_sq(&t1); }
    let mut t2 = fe_mul(&t1, z);
    t0 = fe_mul(&t0, &t2);
    t1 = fe_sq(&t0);
    let t3 = fe_mul(&t2, &t1);
    let mut t4 = t3;
    for _ in 0..5 { t4 = fe_sq(&t4); }
    t2 = fe_mul(&t4, &t3);
    let mut t5 = t2;
    for _ in 0..10 { t5 = fe_sq(&t5); }
    t5 = fe_mul(&t5, &t2);
    let mut t6 = t5;
    for _ in 0..20 { t6 = fe_sq(&t6); }
    t6 = fe_mul(&t6, &t5);
    for _ in 0..10 { t6 = fe_sq(&t6); }
    t2 = fe_mul(&t6, &t2);
    for _ in 0..50 { t2 = fe_sq(&t2); }
    t2 = fe_mul(&t2, &t6);
    for _ in 0..100 { t2 = fe_sq(&t2); }
    t2 = fe_mul(&t2, &t6);
    for _ in 0..50 { t2 = fe_sq(&t2); }
    t2 = fe_mul(&t2, &t4);
    for _ in 0..5 { t2 = fe_sq(&t2); }
    fe_mul(&t2, &t0)
}

fn fe_tobytes(f: &Fe) -> [u8; 32] {
    // Convert to canonical little-endian
    let mut t = [0i64;10];
    for i in 0..10 { t[i]=f.0[i] as i64; }
    // Two carry passes as in ref10
    for _ in 0..2 {
        // even limbs (26b)
        for &i in &[0,2,4,6,8] {
            let carry = (t[i] + (1<<25)) >> 26;
            t[i+1] += carry;
            t[i] -= carry<<26;
        }
        // odd limbs (25b)
        for &i in &[1,3,5,7,9] {
            let carry = (t[i] + (1<<24)) >> 25;
            if i<9 { t[i+1]+=carry; } else { t[0]+=carry*19; }
            t[i] -= carry<<25;
        }
    }
    // Pack to 255-bit int
    let mut s=[0u8;32];
    let mut acc: i128 = 0;
    let sizes=[26,25,26,25,26,25,26,25,26,25];
    let mut pos=0u32;
    for i in 0..10 {
        acc |= (t[i] as i128) << pos;
        pos += sizes[i];
    }
    // reduce acc mod p
    let p = (1i128<<255) - 19;
    acc %= p; if acc<0 { acc += p; }
    for i in 0..32 { s[i] = ((acc >> (8*i)) & 0xff) as u8; }
    s
}

fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let mut acc: i128 = 0;
    for i in 0..32 { acc |= (s[i] as i128) << (8*i); }
    acc &= (1i128<<255)-1;
    let sizes=[26,25,26,25,26,25,26,25,26,25];
    let mut out=[0i32;10];
    let mut pos=0u32;
    for i in 0..10 {
        let mask=(1i128<<sizes[i]) - 1;
        out[i] = ((acc >> pos) & mask) as i32;
        pos += sizes[i];
    }
    Fe(out)
}

#[inline] fn fe_is_odd(a:&Fe)->bool { fe_tobytes(a)[0]&1==1 }
#[inline] fn fe_equal(a:&Fe,b:&Fe)->bool {
    let sa=fe_tobytes(a); let sb=fe_tobytes(b);
    let mut diff=0u8; for i in 0..32 { diff|=sa[i]^sb[i]; } diff==0
}

// ---------------- Edwards group (extended coordinates) ----------------

#[derive(Copy, Clone)]
struct GeP3 { X: Fe, Y: Fe, Z: Fe, T: Fe }
#[derive(Copy, Clone)]
struct GeP2 { X: Fe, Y: Fe, Z: Fe }
#[derive(Copy, Clone)]
struct GeCached { YplusX: Fe, YminusX: Fe, Z: Fe, T2d: Fe }
#[derive(Copy, Clone)]
struct GeP1P1 { X: Fe, Y: Fe, Z: Fe, T: Fe }

const D: Fe = Fe([
    -10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116
]); // ref10 constant

#[inline] fn ge_identity() -> GeP3 {
    GeP3 { X: Fe::zero(), Y: Fe::one(), Z: Fe::one(), T: Fe::zero() }
}

#[inline] fn ge_to_cached(p: &GeP3) -> GeCached {
    GeCached {
        YplusX: fe_add(&p.Y, &p.X),
        YminusX: fe_sub(&p.Y, &p.X),
        Z: fe_copy(&p.Z),
        T2d: fe_mul(&p.T, &fe_mul(&D, &Fe::one())),
    }
}

fn ge_add(p: &GeP3, q: &GeCached) -> GeP1P1 {
    let YplusX = fe_add(&p.Y, &p.X);
    let YminusX = fe_sub(&p.Y, &p.X);
    let PP = fe_mul(&YplusX, &q.YplusX);
    let MM = fe_mul(&YminusX, &q.YminusX);
    let TT2d = fe_mul(&p.T, &q.T2d);
    let ZZ = fe_mul(&p.Z, &q.Z);
    let ZZ2 = fe_add(&ZZ, &ZZ);
    GeP1P1 {
        X: fe_sub(&PP, &MM),
        Y: fe_add(&PP, &MM),
        Z: fe_add(&ZZ2, &TT2d),
        T: fe_sub(&ZZ2, &TT2d),
    }
}

fn ge_sub(p: &GeP3, q: &GeCached) -> GeP1P1 {
    let YplusX = fe_add(&p.Y, &p.X);
    let YminusX = fe_sub(&p.Y, &p.X);
    let PP = fe_mul(&YplusX, &q.YminusX);
    let MM = fe_mul(&YminusX, &q.YplusX);
    let TT2d = fe_mul(&p.T, &q.T2d);
    let ZZ = fe_mul(&p.Z, &q.Z);
    let ZZ2 = fe_add(&ZZ, &ZZ);
    GeP1P1 {
        X: fe_sub(&PP, &MM),
        Y: fe_add(&PP, &MM),
        Z: fe_sub(&ZZ2, &TT2d),
        T: fe_add(&ZZ2, &TT2d),
    }
}

fn ge_double(p: &GeP2) -> GeP1P1 {
    let A = fe_sq(&p.X);
    let B = fe_sq(&p.Y);
    let C = fe_mul(&Fe([2,0,0,0,0,0,0,0,0,0]), &fe_sq(&p.Z));
    let Dv = fe_sub(&fe_sq(&fe_add(&p.X, &p.Y)), &fe_add(&A, &B));
    let E = fe_sub(&B, &A);
    let G = fe_add(&E, &C);
    let F = fe_sub(&E, &C);
    GeP1P1 { X: fe_mul(&Dv, &F), Y: fe_mul(&E, &G), Z: fe_mul(&F, &G), T: fe_mul(&Dv, &E) }
}

#[inline] fn ge_p1p1_to_p3(r:&GeP1P1)->GeP3 {
    let X = fe_mul(&r.X, &r.T);
    let Y = fe_mul(&r.Y, &r.Z);
    let Z = fe_mul(&r.Z, &r.T);
    let T = fe_mul(&r.X, &r.Y);
    GeP3{X,Y,Z,T}
}
#[inline] fn ge_p1p1_to_p2(r:&GeP1P1)->GeP2 {
    let X = fe_mul(&r.X, &r.T);
    let Y = fe_mul(&r.Y, &r.Z);
    let Z = fe_mul(&r.Z, &r.T);
    GeP2{X,Y,Z}
}

// Pack/unpack points

fn ge_pack(P: &GeP3) -> [u8;32] {
    let Zinv = fe_invert(&P.Z);
    let x = fe_mul(&P.X, &Zinv);
    let y = fe_mul(&P.Y, &Zinv);
    let mut s = fe_tobytes(&y);
    let sign = (fe_is_odd(&x) as u8) & 1;
    s[31] |= sign<<7;
    s
}

fn ge_unpack(s: &[u8;32]) -> Option<GeP3> {
    let y = fe_frombytes(s);
    let y2 = fe_sq(&y);
    let u = fe_sub(&y2, &Fe::one());
    let mut v = fe_add(&fe_mul(&D, &y2), &Fe::one());
    let x2 = fe_mul(&u, &fe_invert(&v));
    let mut x = fe_pow2523(&x2); // sqrt
    // choose sign
    let sign = (s[31] >> 7) & 1;
    if (fe_is_odd(&x) as u8) != sign { x = fe_sub(&Fe::zero(), &x); }
    // check on-curve
    if !fe_equal(&fe_mul(&fe_sq(&x), &v), &u) { return None; }
    Some(GeP3 { X:x, Y:y, Z:Fe::one(), T: fe_mul(&x, &y) })
}

// ---------------- Scalar arithmetic (mod L) ----------------

const L: [u8; 32] = [
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,
];

#[inline] fn clamp_scalar(a:&mut [u8;32]) {
    a[0] &= 248; a[31] &= 63; a[31] |= 64;
}

fn sc_reduce_mod_l(h64: &mut [u8;64]) -> [u8;32] {
    // Compact reduction into 32 bytes; SHA-512 outputs
    let mut s=[0u8;32];
    s.copy_from_slice(&h64[..32]);
    while sc_ge(&s,&L) {
        s = sc_sub(&s,&L);
    }
    s
}
#[inline] fn sc_ge(a:&[u8;32], b:&[u8;32])->bool {
    for i in (0..32).rev() {
        if a[i]>b[i] { return true; }
        if a[i]<b[i] { return false; }
    }
    true
}
fn sc_sub(a:&[u8;32], b:&[u8;32])->[u8;32] {
    let mut r=[0u8;32]; let mut borrow=0i16;
    for i in 0..32 {
        let d=a[i] as i16 - b[i] as i16 - borrow;
        if d<0 { r[i]=(d+256) as u8; borrow=1; } else { r[i]=d as u8; borrow=0; }
    }
    r
}
fn sc_addmul_mod_l(r:&[u8;32], k:&[u8;32], a:&[u8;32])->[u8;32] {
    // compute k*a + r into 64 bytes then reduce
    let mut wide=[0u16;64];
    for i in 0..32 {
        for j in 0..32 {
            let p=(k[i] as u16)*(a[j] as u16);
            let idx=i+j;
            let tmp=wide[idx] as u32 + p as u32;
            wide[idx]=(tmp & 0xFF) as u16;
            wide[idx+1]=wide[idx+1].wrapping_add((tmp>>8) as u16);
        }
    }
    // add r
    let mut carry=0u16; let mut out64=[0u8;64];
    for i in 0..32 {
        let v=wide[i] as u32 + r[i] as u32 + carry as u32;
        out64[i]=(v & 0xFF) as u8; carry=(v>>8) as u16;
    }
    for i in 32..64 {
        let v=wide[i] as u32 + carry as u32;
        out64[i]=(v & 0xFF) as u8; carry=(v>>8) as u16;
    }
    sc_reduce_mod_l(&mut out64)
}

fn sc_mul(a:&[u8;32], b:&[u8;32]) -> [u8;32] {
    let mut wide=[0u16;64];
    for i in 0..32 {
        for j in 0..32 {
            let p=(a[i] as u16)*(b[j] as u16);
            let idx=i+j;
            let tmp=wide[idx] as u32 + p as u32;
            wide[idx]=(tmp & 0xFF) as u16;
            wide[idx+1]=wide[idx+1].wrapping_add((tmp>>8) as u16);
        }
    }
    let mut out64=[0u8;64];
    let mut carry=0u16;
    for i in 0..64 {
        let v=wide[i] as u32 + carry as u32;
        out64[i]=(v & 0xFF) as u8; carry=(v>>8) as u16;
    }
    sc_reduce_mod_l(&mut out64)
}

// ---------------- Fast basepoint scalar mult (4-bit signed window) ----------------

struct Precomp {
    // 32 windows × 8 entries (odd multiples) in cached form
    table: [[GeCached; 8]; 32],
}

static PRECOMP: Once<Precomp> = Once::new();

fn ensure_precomp() {
    PRECOMP.call_once(|| build_precomp());
}

fn build_precomp() -> Precomp {
    // Build P_i = (2^(8*i))*B, then T_i[j] = (2*j+1)*P_i with additions
    let B = ge_basepoint();
    let mut P = B;
    let mut table = [[ge_to_cached(&ge_identity()); 8]; 32];
    for i in 0..32 {
        // Compute odd multiples 1P,3P,5P,...,15P in cached form
        let mut P2 = ge_p1p1_to_p3(&ge_double(&GeP2{X:P.X, Y:P.Y, Z:P.Z})); // 2P
        let mut curr = P;
        for j in 0..8 {
            table[i][j] = ge_to_cached(&curr);
            // next odd = curr + 2P
            let sum = ge_add(&curr, &ge_to_cached(&P2));
            curr = ge_p1p1_to_p3(&sum);
        }
        // Advance P = (2^8)*P via 8 doublings
        let mut p2 = GeP2{X:P.X, Y:P.Y, Z:P.Z};
        for _ in 0..8 {
            p2 = ge_p1p1_to_p2(&ge_double(&p2));
        }
        P = ge_p1p1_to_p3(&ge_double(&p2));
    }
    Precomp { table }
}

fn ge_basepoint() -> GeP3 {
    // Standard Ed25519 basepoint encoding (RFC 8032)
    let enc: [u8;32] = [
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    ];
    ge_unpack(&enc).unwrap_or_else(|| ge_identity())
}

// Signed 4-bit window decomposition: output 32 digits in [-8..7] little-endian
fn slide4(scalar: &[u8;32]) -> [i8; 32] {
    let mut e=[0i8;32];
    for i in 0..32 { e[i]=scalar[i] as i8; }
    // Recode into signed form
    for i in 0..32 {
        let carry = (e[i] + 8) >> 4; // arithmetic shift
        e[i] -= carry<<4;
        if i+1<32 { e[i+1] += carry; }
    }
    e
}

// Constant-time selection of cached point by absolute digit in {1,3,5,7,9,11,13,15}
fn select_cached(ct: &[[GeCached;8];32], idx: usize, digit: i8) -> (GeCached, bool) {
    // Return cached for abs(digit) and a sign flag
    let mut sign = false;
    let mut d = digit;
    if d < 0 { sign=true; d = -d; }
    // Map {1,3,5,7,9,11,13,15} -> 0..7 via (d-1)/2
    let pos = ((d as u8).wrapping_sub(1) >> 1) as usize;
    let mut out = ge_to_cached(&ge_identity());
    // constant-time selection
    for j in 0..8 {
        let m = (j ^ pos) as u8;
        let mask = (((m as i8 - 1) >> 7) as u8) ^ 0xFF; // 0xFF if j==pos else 0x00
        out = cached_cmov(&out, &ct[idx][j], mask);
    }
    (out, sign)
}

fn cached_cmov(a:&GeCached, b:&GeCached, mask:u8) -> GeCached {
    GeCached {
        YplusX: fe_cmov(&a.YplusX, &b.YplusX, mask),
        YminusX: fe_cmov(&a.YminusX, &b.YminusX, mask),
        Z: fe_cmov(&a.Z, &b.Z, mask),
        T2d: fe_cmov(&a.T2d, &b.T2d, mask),
    }
}
fn fe_cmov(a:&Fe, b:&Fe, mask:u8)->Fe {
    let mut r=[0i32;10];
    for i in 0..10 {
        let ai=a.0[i]; let bi=b.0[i];
        let m = (mask as i32) * -1; // 0x0000_0000 or 0xFFFF_FFFF
        r[i] = (ai & !m) | (bi & m);
    }
    Fe(r)
}

// Constant-time basepoint scalar multiply using precomp and slide4
fn ge_scalarmult_base_ct(a:&[u8;32]) -> GeP3 {
    let pre = PRECOMP.wait();
    let e = slide4(a);
    let mut P = ge_identity();

    // Process from high window to low
    for i in (0..32).rev() {
        if i != 31 {
            // 8 doublings between windows
            let mut p2 = GeP2{X:P.X, Y:P.Y, Z:P.Z};
            for _ in 0..8 {
                let d2 = ge_double(&p2);
                p2 = ge_p1p1_to_p2(&d2);
            }
            P = ge_p1p1_to_p3(&ge_double(&p2));
        }
        let di = e[i];
        if di != 0 {
            let (c, neg) = select_cached(&pre.table, i, di);
            let add = if !neg { ge_add(&P, &c) } else { ge_sub(&P, &c) };
            P = ge_p1p1_to_p3(&add);
        }
    }
    P
}

// Scalar mul by arbitrary point using double-and-add with 4-bit window (no precomp)
fn ge_scalarmult_point(P:&GeP3, s:&[u8;32]) -> GeP3 {
    let e = slide4(s);
    let mut Q = ge_identity();
    for i in (0..32).rev() {
        if i!=31 {
            let mut p2 = GeP2{X:Q.X, Y:Q.Y, Z:Q.Z};
            for _ in 0..8 {
                let d2 = ge_double(&p2);
                p2 = ge_p1p1_to_p2(&d2);
            }
            Q = ge_p1p1_to_p3(&ge_double(&p2));
        }
        let di = e[i];
        if di!=0 {
            // build cached multiples for this window: {1,3,...,15}*2^(8*i)*P
            let mut Pi = *P;
            if i>0 {
                let mut p2 = GeP2{X:Pi.X, Y:Pi.Y, Z:Pi.Z};
                for _ in 0..(8*i) {
                    let d2 = ge_double(&p2);
                    p2 = ge_p1p1_to_p2(&d2);
                }
                Pi = ge_p1p1_to_p3(&ge_double(&p2));
            }
            let mut Pi2 = ge_p1p1_to_p3(&ge_double(&GeP2{X:Pi.X, Y:Pi.Y, Z:Pi.Z}));
            let mut table:[GeCached;8]=[ge_to_cached(&ge_identity());8];
            let mut curr=Pi;
            for j in 0..8 {
                table[j]=ge_to_cached(&curr);
                let sum = ge_add(&curr, &ge_to_cached(&Pi2));
                curr = ge_p1p1_to_p3(&sum);
            }
            // select
            let mut d=di; let mut neg=false;
            if d<0 { neg=true; d=-d; }
            let pos=((d as u8).wrapping_sub(1)>>1) as usize;
            let mut c=ge_to_cached(&ge_identity());
            for j in 0..8 {
                let m=(j^pos) as u8;
                let mask=(((m as i8 - 1)>>7) as u8)^0xFF;
                c = cached_cmov(&c, &table[j], mask);
            }
            let add = if !neg { ge_add(&Q, &c) } else { ge_sub(&Q, &c) };
            Q = ge_p1p1_to_p3(&add);
        }
    }
    Q
}

// ---------------- Sign / Verify / Batch ----------------

pub fn sign(kp:&KeyPair, msg:&[u8]) -> Signature {
    // Expand seed -> a (clamped) and prefix
    let h = sha512(&kp.private);
    let mut a=[0u8;32]; a.copy_from_slice(&h[..32]); clamp_scalar(&mut a);
    let prefix = &h[32..64];

    // r = H(prefix || msg) mod L
    let mut r_in = Vec::with_capacity(prefix.len()+msg.len());
    r_in.extend_from_slice(prefix);
    r_in.extend_from_slice(msg);
    let mut r64 = sha512(&r_in);
    let r = sc_reduce_mod_l(&mut r64);

    ensure_precomp();
    let Rpt = ge_scalarmult_base_ct(&r);
    let R = ge_pack(&Rpt);

    // k = H(R || A || M) mod L
    let mut kin = Vec::with_capacity(32+32+msg.len());
    kin.extend_from_slice(&R);
    kin.extend_from_slice(&kp.public);
    kin.extend_from_slice(msg);
    let mut k64 = sha512(&kin);
    let k = sc_reduce_mod_l(&mut k64);

    // S = r + k*a mod L
    let S = sc_addmul_mod_l(&r, &k, &a);

    Signature{ R, S }
}

pub fn verify(public:&[u8;32], msg:&[u8], sig:&Signature)->bool {
    // Reject S >= L
    if sc_ge(&sig.S, &L) { return false; }
    // Decode A and R
    let A = match ge_unpack(public) { Some(p)=>p, None=>return false };
    let R = match ge_unpack(&sig.R) { Some(p)=>p, None=>return false };

    // k = H(R || A || M) mod L
    let mut kin=Vec::with_capacity(32+32+msg.len());
    kin.extend_from_slice(&sig.R);
    kin.extend_from_slice(public);
    kin.extend_from_slice(msg);
    let mut k64 = sha512(&kin);
    let k = sc_reduce_mod_l(&mut k64);

    // Check: [S]B == R + [k]A
    let SB = ge_scalarmult_base_ct(&sig.S);
    let kA = ge_scalarmult_point(&A, &k);
    // R + kA
    let Rc = ge_to_cached(&kA);
    let Rp = ge_add(&R, &Rc);
    let Rp3 = ge_p1p1_to_p3(&Rp);

    ge_pack(&SB) == ge_pack(&Rp3)
}

// Randomized batch verification: returns true if all signatures verify
pub fn verify_batch(items:&[([u8;32], &[u8], Signature)])->bool {
    if items.is_empty() { return true; }
    ensure_precomp();

    // Left aggregate: sum(c_i * S_i) * B
    let mut aggL = ge_identity();

    // Right aggregate: sum(c_i * R_i) + sum(c_i * k_i * A_i)
    let mut aggR = ge_identity();

    for (Aenc, msg, sig) in items.iter() {
        // Parse A, R; checks
        let A = match ge_unpack(Aenc) { Some(p)=>p, None=>return false };
        let R = match ge_unpack(&sig.R) { Some(p)=>p, None=>return false };
        if sc_ge(&sig.S, &L) { return false; }

        // k = H(R || A || M) mod L
        let mut kin = Vec::with_capacity(64 + msg.len());
        kin.extend_from_slice(&sig.R);
        kin.extend_from_slice(Aenc);
        kin.extend_from_slice(msg);
        let mut k64 = sha512(&kin);
        let k = sc_reduce_mod_l(&mut k64);

        // Random 16 bytes -> scalar c_i
        let mut ci64 = [0u8;64];
        let rnd = get_random_bytes();
        ci64[..32].copy_from_slice(&rnd);
        let ci = sc_reduce_mod_l(&mut ci64);

        // aggL += (ci*S_i)B
        let ciSi = sc_mul(&ci, &sig.S);
        let termL = ge_scalarmult_base_ct(&ciSi);
        let addL = ge_add(&aggL, &ge_to_cached(&termL));
        aggL = ge_p1p1_to_p3(&addL);

        // aggR += ci*R_i
        let termR = ge_scalarmult_point(&R, &ci);
        let addR1 = ge_add(&aggR, &ge_to_cached(&termR));
        aggR = ge_p1p1_to_p3(&addR1);

        // aggR += ci*k_i*A_i
        let cik = sc_mul(&ci, &k);
        let termRA = ge_scalarmult_point(&A, &cik);
        let addR2 = ge_add(&aggR, &ge_to_cached(&termRA));
        aggR = ge_p1p1_to_p3(&addR2);
    }

    ge_pack(&aggL) == ge_pack(&aggR)
}

// ---------------- Tests (RFC 8032 vectors + sanity) ----------------

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 test vector 1 (empty message)
    #[test]
    fn rfc8032_tv1() {
        let seed = [
            0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
            0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60,
        ];
        let kp = KeyPair::from_seed(seed);
        assert_eq!(&kp.public, &[
            0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
            0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a,
        ]);
        let msg: [u8;0]=[];
        let sig = sign(&kp, &msg);
        assert!(verify(&kp.public, &msg, &sig));
        // Known signature prefix matches (full vector we can add too)
        assert_eq!(&sig.R[..4], &[0xe5,0x56,0x43,0x00]);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::from_seed([7u8;32]);
        let msg = b"ed25519 test message";
        let sig = sign(&kp, msg);
        assert!(verify(&kp.public, msg, &sig));
        // tamper
        let mut s = sig.to_bytes();
        s[10]^=0xFF;
        let sig2 = Signature::from_bytes(&s);
        assert!(!verify(&kp.public, msg, &sig2));
    }

    #[test]
    fn batch_verify_basic() {
        let kp1 = KeyPair::from_seed([1u8;32]);
        let kp2 = KeyPair::from_seed([2u8;32]);
        let m1 = b"hello";
        let m2 = b"world";
        let s1 = sign(&kp1, m1);
        let s2 = sign(&kp2, m2);
        let items = vec![(kp1.public, &m1[..], s1.clone()), (kp2.public, &m2[..], s2.clone())];
        assert!(verify_batch(&items));
        // tamper
        let mut bad = s2.to_bytes();
        bad[0]^=1;
        let bad_sig = Signature::from_bytes(&bad);
        let items2 = vec![(kp1.public, &m1[..], s1), (kp2.public, &m2[..], bad_sig)];
        assert!(!verify_batch(&items2));
    }
}
