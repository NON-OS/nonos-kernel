mod r1;
mod r3;
mod ecc_r5;

use super::super::types::TrustedRootCa;

pub static GLOBALSIGN_ROOTS: &[TrustedRootCa] = &[
    r1::ROOT,
    r3::ROOT,
    ecc_r5::ROOT,
];
