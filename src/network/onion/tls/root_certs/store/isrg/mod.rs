mod x1;
mod x2;

use super::super::types::TrustedRootCa;

pub static ISRG_ROOTS: &[TrustedRootCa] = &[
    x1::ROOT,
    x2::ROOT,
];
