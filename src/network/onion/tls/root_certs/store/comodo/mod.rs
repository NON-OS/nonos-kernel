mod rsa;
mod usertrust_rsa;
mod usertrust_ecc;

use super::super::types::TrustedRootCa;

pub static COMODO_ROOTS: &[TrustedRootCa] = &[
    rsa::ROOT,
    usertrust_rsa::ROOT,
    usertrust_ecc::ROOT,
];
