mod oiste_server_root_ecc_g1;
mod oiste_server_root_rsa_g1;
mod oiste_wisekey_global_root_gb_ca;
mod oiste_wisekey_global_root_gc_ca;

use super::super::types::TrustedRootCa;

pub static OISTE_ROOTS: &[TrustedRootCa] = &[
    oiste_server_root_ecc_g1::ROOT,
    oiste_server_root_rsa_g1::ROOT,
    oiste_wisekey_global_root_gb_ca::ROOT,
    oiste_wisekey_global_root_gc_ca::ROOT,
];
