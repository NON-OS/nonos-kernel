mod isrg;
mod digicert;
mod amazon;
mod google;
mod globalsign;
mod entrust;
mod comodo;

use super::types::TrustedRootCa;

pub static TRUSTED_ROOT_GROUPS: &[&[TrustedRootCa]] = &[
    isrg::ISRG_ROOTS,
    digicert::DIGICERT_ROOTS,
    amazon::AMAZON_ROOTS,
    google::GOOGLE_ROOTS,
    globalsign::GLOBALSIGN_ROOTS,
    entrust::ENTRUST_ROOTS,
    comodo::COMODO_ROOTS,
];
