mod amazon_root_ca_1;
mod amazon_root_ca_2;
mod amazon_root_ca_3;
mod amazon_root_ca_4;

use super::super::types::TrustedRootCa;

pub static AMAZON_ROOTS: &[TrustedRootCa] = &[
    amazon_root_ca_1::ROOT,
    amazon_root_ca_2::ROOT,
    amazon_root_ca_3::ROOT,
    amazon_root_ca_4::ROOT,
];
