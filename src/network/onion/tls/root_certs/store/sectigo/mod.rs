mod sectigo_public_server_authentication_roo;
mod sectigo_public_server_authentication_roo_2;

use super::super::types::TrustedRootCa;

pub(super) static SECTIGO_ROOTS: &[TrustedRootCa] = &[
    sectigo_public_server_authentication_roo::ROOT,
    sectigo_public_server_authentication_roo_2::ROOT,
];
