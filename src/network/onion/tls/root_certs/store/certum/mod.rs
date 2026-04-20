mod certum_ec_384_ca;
mod certum_trusted_network_ca;
mod certum_trusted_network_ca_2;
mod certum_trusted_root_ca;

use super::super::types::TrustedRootCa;

pub(super) static CERTUM_ROOTS: &[TrustedRootCa] = &[
    certum_ec_384_ca::ROOT,
    certum_trusted_network_ca::ROOT,
    certum_trusted_network_ca_2::ROOT,
    certum_trusted_root_ca::ROOT,
];
