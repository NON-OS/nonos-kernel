mod ac_raiz_fnmt_rcm_servidores_seguros;
mod atos_trustedroot_2011;
mod atos_trustedroot_root_ca_ecc_tls_2021;
mod atos_trustedroot_root_ca_rsa_tls_2021;
mod certigna;
mod certigna_root_ca;
mod d_trust_br_root_ca_1_2020;
mod d_trust_br_root_ca_2_2023;
mod d_trust_ev_root_ca_1_2020;
mod d_trust_ev_root_ca_2_2023;
mod d_trust_root_class_3_ca_2_2009;
mod d_trust_root_class_3_ca_2_ev_2009;
mod izenpe_com;
mod t_telesec_globalroot_class_2;
mod t_telesec_globalroot_class_3;

use super::super::types::TrustedRootCa;

pub static GOV_EU_ROOTS: &[TrustedRootCa] = &[
    ac_raiz_fnmt_rcm_servidores_seguros::ROOT,
    atos_trustedroot_2011::ROOT,
    atos_trustedroot_root_ca_ecc_tls_2021::ROOT,
    atos_trustedroot_root_ca_rsa_tls_2021::ROOT,
    certigna::ROOT,
    certigna_root_ca::ROOT,
    d_trust_br_root_ca_1_2020::ROOT,
    d_trust_br_root_ca_2_2023::ROOT,
    d_trust_ev_root_ca_1_2020::ROOT,
    d_trust_ev_root_ca_2_2023::ROOT,
    d_trust_root_class_3_ca_2_2009::ROOT,
    d_trust_root_class_3_ca_2_ev_2009::ROOT,
    izenpe_com::ROOT,
    t_telesec_globalroot_class_2::ROOT,
    t_telesec_globalroot_class_3::ROOT,
];
