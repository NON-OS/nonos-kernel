mod actalis_authentication_root_ca;
mod entrust_root_certification_authority;
mod entrust_root_certification_authority_ec1;
mod entrust_root_certification_authority_g2;
mod go_daddy_root_certificate_authority_g2;
mod quovadis_root_ca_1_g3;
mod quovadis_root_ca_2;
mod quovadis_root_ca_2_g3;
mod quovadis_root_ca_3;
mod quovadis_root_ca_3_g3;
mod starfield_root_certificate_authority_g2;
mod starfield_services_root_certificate_auth;

use super::super::types::TrustedRootCa;

pub(super) static ENTRUST_ROOTS: &[TrustedRootCa] = &[
    actalis_authentication_root_ca::ROOT,
    entrust_root_certification_authority::ROOT,
    entrust_root_certification_authority_ec1::ROOT,
    entrust_root_certification_authority_g2::ROOT,
    go_daddy_root_certificate_authority_g2::ROOT,
    quovadis_root_ca_1_g3::ROOT,
    quovadis_root_ca_2::ROOT,
    quovadis_root_ca_2_g3::ROOT,
    quovadis_root_ca_3::ROOT,
    quovadis_root_ca_3_g3::ROOT,
    starfield_root_certificate_authority_g2::ROOT,
    starfield_services_root_certificate_auth::ROOT,
];
