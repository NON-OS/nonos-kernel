mod telia_root_ca_v2;
mod teliasonera_root_ca_v1;

use super::super::types::TrustedRootCa;

pub static TELIA_ROOTS: &[TrustedRootCa] = &[
    telia_root_ca_v2::ROOT,
    teliasonera_root_ca_v1::ROOT,
];
