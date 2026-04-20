mod origin;
mod sop;
mod cors;
mod csp;
mod mixed_content;
mod referrer;
mod hsts;
mod sri;

#[cfg(test)]
#[cfg(test)]
mod tests;

pub use origin::Origin;
pub use sop::{same_origin_check, SopDecision, cookie_origin_matches, storage_origin_key};
pub use cors::{cors_check, CorsResult, CorsRequest, exposed_headers};
pub use csp::{CspPolicy, CspDirective, csp_allows, csp_allows_inline_script, csp_allows_eval};
pub use mixed_content::{block_mixed_content, upgrade_insecure_request, should_block_nosniff};
pub use referrer::{ReferrerPolicy, compute_referrer};
pub use hsts::{HstsCache, HstsEntry};
pub use sri::{parse_integrity, verify_integrity, SriAlgorithm, strongest_algorithm, SriHash};
