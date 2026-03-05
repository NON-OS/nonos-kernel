// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

const TRACKING_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_cid",
    "utm_reader",
    "utm_name",
    "utm_social",
    "utm_social-type",
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "mc_eid",
    "mc_cid",
    "oly_enc_id",
    "oly_anon_id",
    "_openstat",
    "vero_id",
    "vero_conv",
    "yclid",
    "ymclid",
    "wickedid",
    "twclid",
    "igshid",
    "li_fat_id",
    "li_fat_id_hm",
    "s_kwcid",
    "ef_id",
    "ref",
    "ref_",
    "source",
    "src",
    "campaign",
    "affiliate",
    "partner",
    "promo",
    "trk",
    "tracking",
    "track",
    "clickid",
    "click_id",
    "hsa_acc",
    "hsa_cam",
    "hsa_grp",
    "hsa_ad",
    "hsa_src",
    "hsa_tgt",
    "hsa_kw",
    "hsa_mt",
    "hsa_net",
    "hsa_ver",
    "zanpid",
    "irclickid",
    "irgwc",
    "obOrigUrl",
    "_ga",
    "_gl",
    "__hssc",
    "__hstc",
    "__hsfp",
    "hsCtaTracking",
    "mkt_tok",
    "elqTrackId",
    "elqTrack",
    "assetType",
    "assetId",
    "recipientId",
    "firedFrom",
    "email_source",
    "email_medium",
    "email_campaign",
    "spm",
    "algo_pvid",
    "algo_expid",
    "btsid",
    "ws_ab_test",
    "algo_exp_id",
];

pub fn strip_tracking_params(url: &str) -> String {
    let (base, query) = match url.find('?') {
        Some(pos) => (&url[..pos], Some(&url[pos + 1..])),
        None => (url, None),
    };

    let fragment = match base.find('#') {
        Some(pos) => Some(&base[pos..]),
        None => None,
    };

    let base_no_fragment = match fragment {
        Some(f) => &base[..base.len() - f.len()],
        None => base,
    };

    let Some(query_str) = query else {
        return String::from(url);
    };

    let fragment_in_query = query_str.find('#');
    let (params_str, query_fragment) = match fragment_in_query {
        Some(pos) => (&query_str[..pos], Some(&query_str[pos..])),
        None => (query_str, None),
    };

    let final_fragment = query_fragment.or(fragment);

    let cleaned_params: Vec<&str> = params_str
        .split('&')
        .filter(|param| {
            if let Some(eq_pos) = param.find('=') {
                let key = &param[..eq_pos];
                !is_tracking_param(key)
            } else {
                !is_tracking_param(param)
            }
        })
        .collect();

    let mut result = String::from(base_no_fragment);

    if !cleaned_params.is_empty() {
        result.push('?');
        result.push_str(&cleaned_params.join("&"));
    }

    if let Some(frag) = final_fragment {
        result.push_str(frag);
    }

    result
}

pub fn clean_url(url: &str) -> String {
    let mut cleaned = strip_tracking_params(url);

    cleaned = cleaned.replace("&amp;", "&");

    if cleaned.ends_with('?') {
        cleaned.pop();
    }

    cleaned
}

fn is_tracking_param(key: &str) -> bool {
    let key_lower = key.to_lowercase();

    for param in TRACKING_PARAMS {
        if key_lower == *param {
            return true;
        }
    }

    if key_lower.starts_with("utm_") {
        return true;
    }

    if key_lower.starts_with("_ga") || key_lower.starts_with("_gl") {
        return true;
    }

    if key_lower.starts_with("fb_") || key_lower.starts_with("ig_") {
        return true;
    }

    false
}

pub fn tracking_param_count() -> usize {
    TRACKING_PARAMS.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_params() {
        assert_eq!(
            strip_tracking_params("https://example.com?utm_source=test&page=1"),
            "https://example.com?page=1"
        );

        assert_eq!(
            strip_tracking_params("https://example.com?fbclid=abc123"),
            "https://example.com"
        );

        assert_eq!(
            strip_tracking_params("https://example.com?page=1"),
            "https://example.com?page=1"
        );
    }

    #[test]
    fn test_clean_url() {
        assert_eq!(
            clean_url("https://example.com?utm_source=test&amp;page=1"),
            "https://example.com?page=1"
        );
    }
}
