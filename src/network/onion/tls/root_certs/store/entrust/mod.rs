mod starfield_g2;
mod godaddy_g2;
mod entrust_g2;
mod entrust_ec1;
mod quovadis_2;
mod microsoft_rsa;
mod microsoft_ecc;
mod actalis;

use super::super::types::TrustedRootCa;

pub static ENTRUST_ROOTS: &[TrustedRootCa] = &[
    starfield_g2::ROOT,
    godaddy_g2::ROOT,
    entrust_g2::ROOT,
    entrust_ec1::ROOT,
    quovadis_2::ROOT,
    microsoft_rsa::ROOT,
    microsoft_ecc::ROOT,
    actalis::ROOT,
];
