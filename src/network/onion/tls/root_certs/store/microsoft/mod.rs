mod microsoft_ecc_root_certificate_authority;
mod microsoft_rsa_root_certificate_authority;

use super::super::types::TrustedRootCa;

pub static MICROSOFT_ROOTS: &[TrustedRootCa] = &[
    microsoft_ecc_root_certificate_authority::ROOT,
    microsoft_rsa_root_certificate_authority::ROOT,
];
