mod root_1;
mod root_2;
mod root_3;
mod root_4;

use super::super::types::TrustedRootCa;

pub static AMAZON_ROOTS: &[TrustedRootCa] = &[
    root_1::ROOT,
    root_2::ROOT,
    root_3::ROOT,
    root_4::ROOT,
];
