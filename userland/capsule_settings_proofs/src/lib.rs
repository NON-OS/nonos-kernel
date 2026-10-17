// NONOS Operating System (AGPL-3.0-or-later)
//! Host proofs for the WiFi settings panel. The real panel source is included
//! via #[path] and exercised against synthetic inputs: adapter discovery, the
//! untrusted scan-result parser, and the detect/select/enter-key/connect state
//! machine.

extern crate alloc;

#[path = "../../capsule_settings/src/wifi/interface.rs"]
pub mod interface;
/// The iwlwifi driver's own id table, so the panel's has-a-driver rule is
/// held to it.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../capsule_driver_iwlwifi/src/firmware/family.rs"]
mod iwlwifi_family;

/* How often the Wi-Fi and Network pages ask the DHCP client for its lease. */
#[path = "../../capsule_settings/src/wifi/net_poll.rs"]
pub mod net_poll;

/// The pure WiFi panel modules, grouped so their `super::` references resolve as
/// they do in the capsule. Adapter enumeration (`adapters`) is left out because
/// it calls the broker; the logic it drives (`interface::discover`) is proven.
pub mod wifi;

/// The policy-call error and the pass that reads every stored value when the
/// panel opens; the calls it makes are syscalls and stay out.
pub mod ipc;

// The panel's sections and their row tables, as the capsule has them, so the
// rows the cursor stops on are proved here against the same tables.
#[path = "settings_schema.rs"]
pub mod settings;

// The notes under the rows a person sets, Sound's among them.
#[path = "../../capsule_settings/src/settings/ui/field_note_user.rs"]
pub mod field_note_user;

#[cfg(test)]
mod sound_note_tests;

/// The text buffers the panel's fields type into: UTF-8, edited a whole
/// character at a time.
pub mod text;

/// The answer a Wi-Fi worker thread hands back to the window thread, as libc
/// keeps it for every app with a worker.
#[path = "../../capsule_settings/src/settings/state/wifi_cursor.rs"]
pub mod wifi_cursor;

#[path = "../../libc/src/thread/handoff.rs"]
pub mod handoff;

/// The saved-network record from `nonos_wifi_client`: its slots, its
/// encoding and its sealing, driven with keys the tests choose. The vfs and
/// TPM halves are left out; they are syscalls.
#[cfg(test)]
mod saved;
#[cfg(test)]
use wifi::{join_wire, network};
#[cfg(test)]
#[path = "../../nonos_wifi_client/src/wipe.rs"]
mod wipe;

/* The Qwen model row's tiers, as Settings steps through them. */
#[path = "../../capsule_settings/src/settings/qwen_tier/mod.rs"]
pub mod qwen_tier;

#[cfg(test)]
mod handoff_tests;
#[cfg(test)]
mod hover_scroll_tests;
#[cfg(test)]
mod hover_tests;
#[cfg(test)]
mod hydrate_tests;
#[cfg(test)]
mod interface_tests;
#[cfg(test)]
mod net_poll_tests;
#[cfg(test)]
mod panel_tests;
#[cfg(test)]
mod qwen_tier_tests;
#[cfg(test)]
mod paste_tests;
#[cfg(test)]
mod pending_tests;
#[cfg(test)]
mod section_tests;
#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod slot_tests;
#[cfg(test)]
mod text_tests;
#[cfg(test)]
mod wifi_cursor_tests;
#[cfg(test)]
mod wifi_key_tests;
#[cfg(test)]
mod wire_tests;
