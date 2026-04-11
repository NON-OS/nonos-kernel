mod digicert_assured_id_root_ca;
mod digicert_assured_id_root_g2;
mod digicert_assured_id_root_g3;
mod digicert_global_root_ca;
mod digicert_global_root_g2;
mod digicert_global_root_g3;
mod digicert_high_assurance_ev_root_ca;
mod digicert_tls_ecc_p384_root_g5;
mod digicert_tls_rsa4096_root_g5;
mod digicert_trusted_root_g4;

use super::super::types::TrustedRootCa;

pub static DIGICERT_ROOTS: &[TrustedRootCa] = &[
    digicert_assured_id_root_ca::ROOT,
    digicert_assured_id_root_g2::ROOT,
    digicert_assured_id_root_g3::ROOT,
    digicert_global_root_ca::ROOT,
    digicert_global_root_g2::ROOT,
    digicert_global_root_g3::ROOT,
    digicert_high_assurance_ev_root_ca::ROOT,
    digicert_tls_ecc_p384_root_g5::ROOT,
    digicert_tls_rsa4096_root_g5::ROOT,
    digicert_trusted_root_g4::ROOT,
];
