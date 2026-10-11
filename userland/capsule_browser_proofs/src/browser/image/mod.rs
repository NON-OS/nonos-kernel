// NONOS Operating System (AGPL-3.0-or-later)
/* The decoder under test is pub(super), so it is only pulled in for the tests
 * that exercise it; that keeps the non-test build free of an unused import. */
#[cfg(test)]
#[path = "../../../../base64/src/decode.rs"]
pub mod base64;

#[cfg(test)]
mod base64_tests;

/* The engine's decode path and store, compiled from the capsule. */
#[path = "../../../../capsule_browser/src/browser/image/decode.rs"]
pub mod decode;
#[path = "../../../../capsule_browser/src/browser/image/decode_full.rs"]
pub mod decode_full;
#[path = "../../../../capsule_browser/src/browser/image/ico.rs"]
pub mod ico;
#[path = "../../../../capsule_browser/src/browser/image/ico_dib.rs"]
pub mod ico_dib;
#[path = "../../../../capsule_browser/src/browser/image/ingest.rs"]
pub mod ingest;
#[path = "../../../../capsule_browser/src/browser/image/jpeg.rs"]
pub mod jpeg;
#[path = "../../../../capsule_browser/src/browser/image/plan.rs"]
pub mod plan;
#[path = "../../../../capsule_browser/src/browser/image/plan_vector.rs"]
pub mod plan_vector;
#[path = "../../../../capsule_browser/src/browser/image/resident.rs"]
pub mod resident;
#[path = "../../../../capsule_browser/src/browser/image/shrink.rs"]
pub mod shrink;
#[path = "../../../../capsule_browser/src/browser/image/sniff/mod.rs"]
pub mod sniff;
#[path = "../../../../capsule_browser/src/browser/image/store.rs"]
pub mod store;
#[path = "../../../../capsule_browser/src/browser/image/store_blur.rs"]
pub mod store_blur;
#[path = "../../../../capsule_browser/src/browser/image/store_budget.rs"]
pub mod store_budget;
#[path = "../../../../capsule_browser/src/browser/image/store_entry.rs"]
pub mod store_entry;
#[path = "../../../../capsule_browser/src/browser/image/store_hint.rs"]
pub mod store_hint;
#[path = "../../../../capsule_browser/src/browser/image/store_lookup.rs"]
pub mod store_lookup;
#[path = "../../../../capsule_browser/src/browser/image/store_natural.rs"]
pub mod store_natural;
#[path = "../../../../capsule_browser/src/browser/image/svg/mod.rs"]
pub mod svg;
#[path = "../../../../capsule_browser/src/browser/image/webp/mod.rs"]
pub mod webp;

#[cfg(test)]
mod svg_tests;

pub use ingest::{ingest, note_img_size, note_size};
pub use store::{Decoded, Store};
