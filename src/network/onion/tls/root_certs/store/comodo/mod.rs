mod comodo_certification_authority;
mod comodo_ecc_certification_authority;
mod comodo_rsa_certification_authority;
mod usertrust_ecc_certification_authority;
mod usertrust_rsa_certification_authority;

use super::super::types::TrustedRootCa;

pub(super) static COMODO_ROOTS: &[TrustedRootCa] = &[
    comodo_certification_authority::ROOT,
    comodo_ecc_certification_authority::ROOT,
    comodo_rsa_certification_authority::ROOT,
    usertrust_ecc_certification_authority::ROOT,
    usertrust_rsa_certification_authority::ROOT,
];
