mod isrg_root_x1;
mod isrg_root_x2;

use super::super::types::TrustedRootCa;

pub static ISRG_ROOTS: &[TrustedRootCa] = &[
    isrg_root_x1::ROOT,
    isrg_root_x2::ROOT,
];
