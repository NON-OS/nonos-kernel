mod ;
mod cfca_ev_root;
mod emsign_ecc_root_ca_c3;
mod emsign_ecc_root_ca_g3;
mod emsign_root_ca_c1;
mod emsign_root_ca_g1;
mod hongkong_post_root_ca_3;
mod security_communication_ecc_rootca1;
mod twca_cyber_root_ca;
mod twca_global_root_ca;
mod twca_root_certification_authority;

use super::super::types::TrustedRootCa;

pub static GOV_APAC_ROOTS: &[TrustedRootCa] = &[
    ::ROOT,
    cfca_ev_root::ROOT,
    emsign_ecc_root_ca_c3::ROOT,
    emsign_ecc_root_ca_g3::ROOT,
    emsign_root_ca_c1::ROOT,
    emsign_root_ca_g1::ROOT,
    hongkong_post_root_ca_3::ROOT,
    security_communication_ecc_rootca1::ROOT,
    twca_cyber_root_ca::ROOT,
    twca_global_root_ca::ROOT,
    twca_root_certification_authority::ROOT,
];
