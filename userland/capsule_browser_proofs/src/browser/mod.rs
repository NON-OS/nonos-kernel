// NONOS Operating System (AGPL-3.0-or-later)
//! The engine's own module tree, compiled from the capsule's source. These
//! used to be hand-written mirrors listing every file, which drifted: the dom
//! mirror had been missing `measure` and `serialize` for a while. Pointing at
//! the real mod.rs keeps one list of what the engine is made of.

#[path = "../../../capsule_browser/src/browser/css/mod.rs"]
pub mod css;
#[path = "../../../capsule_browser/src/browser/dom/mod.rs"]
pub mod dom;
#[path = "../../../capsule_browser/src/browser/event/dom_print.rs"]
pub mod dom_print;
#[path = "../../../capsule_browser/src/browser/fonts/mod.rs"]
pub mod fonts;
#[path = "../../../capsule_browser/src/browser/html/mod.rs"]
pub mod html;
#[path = "../../../capsule_browser/src/browser/layout/mod.rs"]
pub mod layout;
#[path = "../../../capsule_browser/src/browser/omnibox/mod.rs"]
pub mod omnibox;
#[path = "../../../capsule_browser/src/browser/ui/mod.rs"]
pub mod ui;
#[path = "../../../capsule_browser/src/browser/url/mod.rs"]
pub mod url;
#[path = "../../../capsule_browser/src/browser/short_name.rs"]
pub mod short_name;

/* js keeps its mirror: the interpreter modules under test are private to the
 * capsule and nothing outside the engine has cause to reach them. */
pub mod event;
pub mod image;
pub mod js;
pub mod manifest;

#[path = "../../../capsule_browser/src/browser/net/recv_pending.rs"]
pub mod recv_pending;

/* The fetch machine: its socket calls behind a trait, its TLS the real one. */
pub mod fetch;
#[path = "../../../capsule_browser/src/browser/cookie/mod.rs"]
pub mod cookie;
#[path = "../../../capsule_browser/src/browser/http/mod.rs"]
pub mod http;
pub mod net;
#[cfg(test)]
#[path = "../../../capsule_browser/src/browser/proxy/said.rs"]
mod said;
#[cfg(test)]
mod said_tests;
pub use tls_proofs as tls13;
#[path = "../../../capsule_browser/src/browser/fetch/enqueue_css/sheet.rs"]
pub mod sheet;
