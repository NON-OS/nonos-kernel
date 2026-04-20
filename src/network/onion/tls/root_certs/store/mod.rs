mod affirmtrust;
mod amazon;
mod buypass;
mod certum;
mod comodo;
mod digicert;
mod entrust;
mod globalsign;
mod google;
mod government_apac;
mod government_eu;
mod identrust;
mod isrg;
mod microsoft;
mod oiste;
mod regional;
mod sectigo;
mod ssl_com;
mod swisssign;
mod telia;
mod trustwave;

use super::types::TrustedRootCa;

pub static TRUSTED_ROOT_GROUPS: &[&[TrustedRootCa]] = &[
    affirmtrust::AFFIRMTRUST_ROOTS,
    amazon::AMAZON_ROOTS,
    buypass::BUYPASS_ROOTS,
    certum::CERTUM_ROOTS,
    comodo::COMODO_ROOTS,
    digicert::DIGICERT_ROOTS,
    entrust::ENTRUST_ROOTS,
    globalsign::GLOBALSIGN_ROOTS,
    google::GOOGLE_ROOTS,
    government_apac::GOV_APAC_ROOTS,
    government_eu::GOV_EU_ROOTS,
    identrust::IDENTRUST_ROOTS,
    isrg::ISRG_ROOTS,
    microsoft::MICROSOFT_ROOTS,
    oiste::OISTE_ROOTS,
    regional::REGIONAL_ROOTS,
    sectigo::SECTIGO_ROOTS,
    ssl_com::SSL_COM_ROOTS,
    swisssign::SWISSSIGN_ROOTS,
    telia::TELIA_ROOTS,
    trustwave::TRUSTWAVE_ROOTS,
];
