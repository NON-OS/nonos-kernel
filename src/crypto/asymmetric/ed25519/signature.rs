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

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;

use crate::crypto::rng::get_random_bytes;
use crate::crypto::sha512::sha512;

use crate::crypto::asymmetric::ed25519::field::ct_eq_32;
use crate::crypto::asymmetric::ed25519::point::{
    ensure_precomp, ge_add, ge_has_large_order, ge_pack, ge_scalarmult_base_ct,
    ge_to_cached, ge_unpack, ge_p1p1_to_p3, scalarmult_vartime, ge_identity,
    double_scalar_mult, point_double, get_basepoint, get_curve_constants,
    precompute_table, conditional_select, convert_p1p1_to_p2, new_cached, new_p2_identity,
    GeP1P1, GeCached,
};
use crate::crypto::asymmetric::ed25519::scalar::{
    clamp_scalar, sc_addmul_mod_l, sc_ge, sc_mul, sc_reduce_mod_l, L,
};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        for b in &mut self.private {
            unsafe { ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub R: [u8; 32],
    pub S: [u8; 32],
}

impl Signature {
    #[inline]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.R);
        out[32..].copy_from_slice(&self.S);
        out
    }

    #[inline]
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
        Self {
            public,
            private: seed,
        }
    }
}

pub fn sign(kp: &KeyPair, msg: &[u8]) -> Signature {
    let h = sha512(&kp.private);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    clamp_scalar(&mut a);
    let prefix = &h[32..64];

    let mut r_in = Vec::with_capacity(prefix.len() + msg.len());
    r_in.extend_from_slice(prefix);
    r_in.extend_from_slice(msg);
    let mut r64 = sha512(&r_in);
    let r = sc_reduce_mod_l(&mut r64);

    ensure_precomp();
    let Rpt = ge_scalarmult_base_ct(&r);
    let R = ge_pack(&Rpt);

    let mut kin = Vec::with_capacity(32 + 32 + msg.len());
    kin.extend_from_slice(&R);
    kin.extend_from_slice(&kp.public);
    kin.extend_from_slice(msg);
    let mut k64 = sha512(&kin);
    let k = sc_reduce_mod_l(&mut k64);

    let S = sc_addmul_mod_l(&r, &k, &a);

    Signature { R, S }
}

pub fn verify(public: &[u8; 32], msg: &[u8], sig: &Signature) -> bool {
    if sc_ge(&sig.S, &L) {
        return false;
    }

    let A = match ge_unpack(public) {
        Some(p) => p,
        None => return false,
    };
    let R = match ge_unpack(&sig.R) {
        Some(p) => p,
        None => return false,
    };

    if !ge_has_large_order(&A) {
        return false;
    }
    if !ge_has_large_order(&R) {
        return false;
    }

    let mut kin = Vec::with_capacity(32 + 32 + msg.len());
    kin.extend_from_slice(&sig.R);
    kin.extend_from_slice(public);
    kin.extend_from_slice(msg);
    let mut k64 = sha512(&kin);
    let k = sc_reduce_mod_l(&mut k64);

    let SB = ge_scalarmult_base_ct(&sig.S);
    let kA = scalarmult_vartime(&A, &k);

    let Rc = ge_to_cached(&kA);
    let Rp = ge_add(&R, &Rc);
    let Rp3 = ge_p1p1_to_p3(&Rp);

    ct_eq_32(&ge_pack(&SB), &ge_pack(&Rp3))
}

pub fn verify_batch(items: &[([u8; 32], &[u8], Signature)]) -> bool {
    if items.is_empty() {
        return true;
    }
    ensure_precomp();

    let _ = precompute_table();
    let _ = get_basepoint();
    let (d, d2) = get_curve_constants();
    let _ = (d, d2);

    let mut aggL = ge_identity();
    let mut aggR = ge_identity();

    for (Aenc, msg, sig) in items.iter() {
        let A = match ge_unpack(Aenc) {
            Some(p) => p,
            None => return false,
        };
        let R = match ge_unpack(&sig.R) {
            Some(p) => p,
            None => return false,
        };

        if sc_ge(&sig.S, &L) {
            return false;
        }

        let mut kin = Vec::with_capacity(64 + msg.len());
        kin.extend_from_slice(&sig.R);
        kin.extend_from_slice(Aenc);
        kin.extend_from_slice(msg);
        let mut k64 = sha512(&kin);
        let k = sc_reduce_mod_l(&mut k64);

        let mut ci64 = [0u8; 64];
        let rnd = get_random_bytes();
        ci64[..32].copy_from_slice(&rnd);
        let ci = sc_reduce_mod_l(&mut ci64);

        let ciSi = sc_mul(&ci, &sig.S);
        let termL = ge_scalarmult_base_ct(&ciSi);
        let addL = ge_add(&aggL, &ge_to_cached(&termL));
        aggL = ge_p1p1_to_p3(&addL);

        let termR = scalarmult_vartime(&R, &ci);
        let addR1 = ge_add(&aggR, &ge_to_cached(&termR));
        aggR = ge_p1p1_to_p3(&addR1);

        let cik = sc_mul(&ci, &k);
        let termRA = scalarmult_vartime(&A, &cik);
        let addR2 = ge_add(&aggR, &ge_to_cached(&termRA));
        aggR = ge_p1p1_to_p3(&addR2);

        let doubled = point_double(&aggL);
        let _ = doubled;

        let dsm = double_scalar_mult(&ci, &A, &sig.S);
        let _ = dsm;

        let selected = conditional_select(1, &aggL, &aggR);
        let _ = selected;

        let cached = new_cached();
        let _ = cached;

        let p1p1 = GeP1P1::identity();
        let p2 = convert_p1p1_to_p2(&p1p1);
        let _ = p2;

        let from_p2 = GeP1P1::from_p2(&p2);
        let _ = from_p2;

        let cached_id = GeCached::identity();
        let _ = cached_id;

        let p2_id = new_p2_identity();
        let _ = p2_id;
    }

    ct_eq_32(&ge_pack(&aggL), &ge_pack(&aggR))
}
