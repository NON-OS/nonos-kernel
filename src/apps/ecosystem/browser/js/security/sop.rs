extern crate alloc;
use super::origin::Origin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SopDecision {
    Allow,
    Block,
}

pub fn same_origin_check(request_url: &str, page_url: &str) -> SopDecision {
    let request_origin = Origin::from_url(request_url);
    let page_origin = Origin::from_url(page_url);
    if request_origin.is_opaque() || page_origin.is_opaque() {
        return SopDecision::Block;
    }
    if request_origin.same_origin(&page_origin) {
        SopDecision::Allow
    } else {
        SopDecision::Block
    }
}

pub fn cookie_origin_matches(cookie_domain: &str, page_url: &str) -> bool {
    let origin = Origin::from_url(page_url);
    origin.host == cookie_domain || origin.host.ends_with(&alloc::format!(".{}", cookie_domain))
}

pub fn storage_origin_key(url: &str) -> alloc::string::String {
    let origin = Origin::from_url(url);
    origin.serialized()
}
