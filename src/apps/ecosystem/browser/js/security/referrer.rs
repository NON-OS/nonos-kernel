extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ReferrerPolicy {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "no-referrer" => Self::NoReferrer,
            "no-referrer-when-downgrade" => Self::NoReferrerWhenDowngrade,
            "origin" => Self::Origin,
            "origin-when-cross-origin" => Self::OriginWhenCrossOrigin,
            "same-origin" => Self::SameOrigin,
            "strict-origin" => Self::StrictOrigin,
            "strict-origin-when-cross-origin" => Self::StrictOriginWhenCrossOrigin,
            "unsafe-url" => Self::UnsafeUrl,
            _ => Self::StrictOriginWhenCrossOrigin,
        }
    }
}

pub fn compute_referrer(policy: ReferrerPolicy, page_url: &str, target_url: &str) -> Option<String> {
    let page = super::origin::Origin::from_url(page_url);
    let target = super::origin::Origin::from_url(target_url);
    let same = page.same_origin(&target);
    let downgrade = page.scheme == "https" && target.scheme == "http";

    match policy {
        ReferrerPolicy::NoReferrer => None,
        ReferrerPolicy::NoReferrerWhenDowngrade => {
            if downgrade { None } else { Some(String::from(page_url)) }
        }
        ReferrerPolicy::Origin => Some(page.serialized()),
        ReferrerPolicy::OriginWhenCrossOrigin => {
            if same { Some(String::from(page_url)) } else { Some(page.serialized()) }
        }
        ReferrerPolicy::SameOrigin => {
            if same { Some(String::from(page_url)) } else { None }
        }
        ReferrerPolicy::StrictOrigin => {
            if downgrade { None } else { Some(page.serialized()) }
        }
        ReferrerPolicy::StrictOriginWhenCrossOrigin => {
            if downgrade { None }
            else if same { Some(String::from(page_url)) }
            else { Some(page.serialized()) }
        }
        ReferrerPolicy::UnsafeUrl => Some(String::from(page_url)),
    }
}
