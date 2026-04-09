mod gts_r1;
mod gts_r2;
mod gts_r3;
mod gts_r4;

use super::super::types::TrustedRootCa;

pub static GOOGLE_ROOTS: &[TrustedRootCa] = &[
    gts_r1::ROOT,
    gts_r2::ROOT,
    gts_r3::ROOT,
    gts_r4::ROOT,
];
