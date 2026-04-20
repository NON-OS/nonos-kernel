mod trustwave_global_certification_authority;
mod trustwave_global_ecc_p256_certification;
mod trustwave_global_ecc_p384_certification;

use super::super::types::TrustedRootCa;

pub static TRUSTWAVE_ROOTS: &[TrustedRootCa] = &[
    trustwave_global_certification_authority::ROOT,
    trustwave_global_ecc_p256_certification::ROOT,
    trustwave_global_ecc_p384_certification::ROOT,
];
