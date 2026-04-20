mod ssl_com_ev_root_certification_authority;
mod ssl_com_ev_root_certification_authority_2;
mod ssl_com_root_certification_authority_ecc;
mod ssl_com_root_certification_authority_rsa;
mod ssl_com_tls_ecc_root_ca_2022;
mod ssl_com_tls_rsa_root_ca_2022;

use super::super::types::TrustedRootCa;

pub(super) static SSL_COM_ROOTS: &[TrustedRootCa] = &[
    ssl_com_ev_root_certification_authority::ROOT,
    ssl_com_ev_root_certification_authority_2::ROOT,
    ssl_com_root_certification_authority_ecc::ROOT,
    ssl_com_root_certification_authority_rsa::ROOT,
    ssl_com_tls_ecc_root_ca_2022::ROOT,
    ssl_com_tls_rsa_root_ca_2022::ROOT,
];
