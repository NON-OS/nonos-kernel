// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use spin::Once;

use crate::crypto::asymmetric::ed25519::field::{
    fe_add, fe_cmov, fe_copy, fe_equal, fe_frombytes, fe_invert, fe_is_odd, fe_is_zero, fe_mul,
    fe_pow2523, fe_sq, fe_sub, fe_tobytes, Fe,
};

#[derive(Copy, Clone)]
pub(crate) struct GeP3 {
    pub(crate) X: Fe,
    pub(crate) Y: Fe,
    pub(crate) Z: Fe,
    pub(crate) T: Fe,
}

#[derive(Copy, Clone)]
pub(crate) struct GeP2 {
    pub(crate) X: Fe,
    pub(crate) Y: Fe,
    pub(crate) Z: Fe,
}

#[derive(Copy, Clone)]
pub(crate) struct GeCached {
    pub(crate) YplusX: Fe,
    pub(crate) YminusX: Fe,
    pub(crate) Z: Fe,
    pub(crate) T2d: Fe,
}

#[derive(Copy, Clone)]
pub(crate) struct GeP1P1 {
    pub(crate) X: Fe,
    pub(crate) Y: Fe,
    pub(crate) Z: Fe,
    pub(crate) T: Fe,
}

pub(crate) const D: Fe = Fe([
    -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448,
    -12055116,
]);

pub(crate) const D2: Fe = Fe([
    -21827220, 27714826, -30745222, 13898782, 229458, -17575632, -12551816, -6495438, -37392896,
    -24110232,
]);

#[inline]
pub(crate) fn ge_identity() -> GeP3 {
    GeP3 {
        X: Fe::zero(),
        Y: Fe::one(),
        Z: Fe::one(),
        T: Fe::zero(),
    }
}

#[inline]
pub(crate) fn ge_to_cached(p: &GeP3) -> GeCached {
    GeCached {
        YplusX: fe_add(&p.Y, &p.X),
        YminusX: fe_sub(&p.Y, &p.X),
        Z: fe_copy(&p.Z),
        T2d: fe_mul(&p.T, &D2),
    }
}

pub(crate) fn ge_add(p: &GeP3, q: &GeCached) -> GeP1P1 {
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

pub(crate) fn ge_sub(p: &GeP3, q: &GeCached) -> GeP1P1 {
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

pub(crate) fn ge_double(p: &GeP2) -> GeP1P1 {
    let XX = fe_sq(&p.X);
    let YY = fe_sq(&p.Y);
    let ZZ2 = fe_add(&fe_sq(&p.Z), &fe_sq(&p.Z));
    let XpY = fe_add(&p.X, &p.Y);
    let XpY2 = fe_sq(&XpY);
    let YYpXX = fe_add(&YY, &XX);
    let YYmXX = fe_sub(&YY, &XX);
    let E = fe_sub(&XpY2, &YYpXX);
    let F = fe_sub(&ZZ2, &YYmXX);
    GeP1P1 {
        X: E,
        Y: YYpXX,
        Z: YYmXX,
        T: F,
    }
}

#[inline]
pub(crate) fn ge_p1p1_to_p3(r: &GeP1P1) -> GeP3 {
    let X = fe_mul(&r.X, &r.T);
    let Y = fe_mul(&r.Y, &r.Z);
    let Z = fe_mul(&r.Z, &r.T);
    let T = fe_mul(&r.X, &r.Y);
    GeP3 { X, Y, Z, T }
}

#[inline]
pub(crate) fn ge_p1p1_to_p2(r: &GeP1P1) -> GeP2 {
    let X = fe_mul(&r.X, &r.T);
    let Y = fe_mul(&r.Y, &r.Z);
    let Z = fe_mul(&r.Z, &r.T);
    GeP2 { X, Y, Z }
}

pub(crate) fn ge_pack(P: &GeP3) -> [u8; 32] {
    let Zinv = fe_invert(&P.Z);
    let x = fe_mul(&P.X, &Zinv);
    let y = fe_mul(&P.Y, &Zinv);
    let mut s = fe_tobytes(&y);
    let sign = (fe_is_odd(&x) as u8) & 1;
    s[31] |= sign << 7;
    s
}

pub(crate) fn ge_unpack(s: &[u8; 32]) -> Option<GeP3> {
    let y = fe_frombytes(s);
    let y2 = fe_sq(&y);
    let u = fe_sub(&y2, &Fe::one());
    let v = fe_add(&fe_mul(&D, &y2), &Fe::one());

    let v2 = fe_sq(&v);
    let v3 = fe_mul(&v2, &v);
    let v4 = fe_sq(&v2);
    let v7 = fe_mul(&v3, &v4);
    let uv3 = fe_mul(&u, &v3);
    let uv7 = fe_mul(&u, &v7);
    let mut x = fe_mul(&uv3, &fe_pow2523(&uv7));

    let x2v = fe_mul(&fe_sq(&x), &v);

    if !fe_equal(&x2v, &u) {
        let sqrtm1 = Fe([
            -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686,
            11406482,
        ]);
        x = fe_mul(&x, &sqrtm1);
        let x2v = fe_mul(&fe_sq(&x), &v);
        if !fe_equal(&x2v, &u) {
            return None;
        }
    }

    let sign = (s[31] >> 7) & 1;
    if (fe_is_odd(&x) as u8) != sign {
        x = fe_sub(&Fe::zero(), &x);
    }

    Some(GeP3 {
        X: x,
        Y: y,
        Z: Fe::one(),
        T: fe_mul(&x, &y),
    })
}

pub(crate) struct Precomp {
    pub(crate) table: [[GeCached; 8]; 32],
}

pub(crate) static PRECOMP: Once<Precomp> = Once::new();

pub(crate) fn ensure_precomp() {
    PRECOMP.call_once(|| build_precomp());
}

fn build_precomp() -> Precomp {
    let B = ge_basepoint();
    let mut P = B;
    let mut table = [[ge_to_cached(&ge_identity()); 8]; 32];
    for i in 0..32 {
        let P2 = ge_p1p1_to_p3(&ge_double(&GeP2 {
            X: P.X,
            Y: P.Y,
            Z: P.Z,
        }));
        let mut curr = P;
        for j in 0..8 {
            table[i][j] = ge_to_cached(&curr);
            let sum = ge_add(&curr, &ge_to_cached(&P2));
            curr = ge_p1p1_to_p3(&sum);
        }
        let mut p2 = GeP2 {
            X: P.X,
            Y: P.Y,
            Z: P.Z,
        };
        for _ in 0..8 {
            p2 = ge_p1p1_to_p2(&ge_double(&p2));
        }
        P = ge_p1p1_to_p3(&ge_double(&p2));
    }
    Precomp { table }
}

pub(crate) fn ge_basepoint() -> GeP3 {
    let enc: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    ge_unpack(&enc).unwrap_or_else(|| ge_identity())
}

pub(crate) fn cached_cmov(a: &GeCached, b: &GeCached, mask: u8) -> GeCached {
    GeCached {
        YplusX: fe_cmov(&a.YplusX, &b.YplusX, mask),
        YminusX: fe_cmov(&a.YminusX, &b.YminusX, mask),
        Z: fe_cmov(&a.Z, &b.Z, mask),
        T2d: fe_cmov(&a.T2d, &b.T2d, mask),
    }
}

pub(crate) fn ge_scalarmult_base_ct(a: &[u8; 32]) -> GeP3 {
    let _ = PRECOMP.wait();
    ge_scalarmult_ct(&ge_basepoint(), a)
}

pub(crate) fn ge_scalarmult_ct(P: &GeP3, scalar: &[u8; 32]) -> GeP3 {
    let mut result = ge_identity();
    let mut temp = *P;

    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (scalar[byte_idx] >> bit_idx) & 1;
      
        let sum = ge_add(&result, &ge_to_cached(&temp));
        let sum_p3 = ge_p1p1_to_p3(&sum);

        let mask = ct_byte_mask(bit);
        result = ge_cmov(&result, &sum_p3, mask);

        let p2 = GeP2 {
            X: temp.X,
            Y: temp.Y,
            Z: temp.Z,
        };
        let doubled = ge_double(&p2);
        temp = ge_p1p1_to_p3(&doubled);
    }

    result
}

#[inline]
pub(crate) fn ct_byte_mask(bit: u8) -> u8 {
    0u8.wrapping_sub(bit)
}

#[inline]
pub(crate) fn ge_cmov(a: &GeP3, b: &GeP3, mask: u8) -> GeP3 {
    GeP3 {
        X: fe_cmov(&a.X, &b.X, mask),
        Y: fe_cmov(&a.Y, &b.Y, mask),
        Z: fe_cmov(&a.Z, &b.Z, mask),
        T: fe_cmov(&a.T, &b.T, mask),
    }
}

pub(crate) fn ge_scalarmult_vartime(P: &GeP3, scalar: &[u8; 32]) -> GeP3 {
    let mut result = ge_identity();
    let mut temp = *P;
    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (scalar[byte_idx] >> bit_idx) & 1;
        if bit == 1 {
            let sum = ge_add(&result, &ge_to_cached(&temp));
            result = ge_p1p1_to_p3(&sum);
        }

        let p2 = GeP2 {
            X: temp.X,
            Y: temp.Y,
            Z: temp.Z,
        };
        let doubled = ge_double(&p2);
        temp = ge_p1p1_to_p3(&doubled);
    }

    result
}

pub(crate) fn ge_scalarmult_point(P: &GeP3, s: &[u8; 32]) -> GeP3 {
    ge_scalarmult_vartime(P, s)
}

pub(crate) fn ge_has_large_order(p: &GeP3) -> bool {
    let p2 = ge_p1p1_to_p3(&ge_double(&GeP2 {
        X: p.X,
        Y: p.Y,
        Z: p.Z,
    }));
    let p4 = ge_p1p1_to_p3(&ge_double(&GeP2 {
        X: p2.X,
        Y: p2.Y,
        Z: p2.Z,
    }));
    let p8 = ge_p1p1_to_p3(&ge_double(&GeP2 {
        X: p4.X,
        Y: p4.Y,
        Z: p4.Z,
    }));

    let x_is_zero = fe_is_zero(&p8.X);
    let y_eq_z = fe_equal(&p8.Y, &p8.Z);

    !(x_is_zero && y_eq_z)
}
