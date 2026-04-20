mod swisssign_gold_ca_g2;
mod swisssign_rsa_tls_root_ca_2022_1;

use super::super::types::TrustedRootCa;

pub(super) static SWISSSIGN_ROOTS: &[TrustedRootCa] = &[
    swisssign_gold_ca_g2::ROOT,
    swisssign_rsa_tls_root_ca_2022_1::ROOT,
];
