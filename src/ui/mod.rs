//! UI module root for NONOS kernel.

#![no_std]

#[cfg(feature = "ui")]
pub mod nonos_cli;
#[cfg(feature = "ui")]
pub mod nonos_event;
#[cfg(feature = "ui")]
pub mod nonos_gui_bridge;
#[cfg(feature = "ui")]
pub mod nonos_keyboard;
#[cfg(feature = "ui")]
pub mod nonos_tui;
#[cfg(feature = "ui")]
pub mod nonos_clipboard;
#[cfg(feature = "ui")]
pub mod nonos_browser;
#[cfg(feature = "ui")]
pub mod nonos_desktop;

#[cfg(feature = "ui")]
pub use nonos_cli as cli;
#[cfg(feature = "ui")]
pub use nonos_event as event;
#[cfg(feature = "ui")]
pub use nonos_gui_bridge as gui_bridge;
#[cfg(feature = "ui")]
pub use nonos_keyboard as keyboard;
#[cfg(feature = "ui")]
pub use nonos_tui as tui;
#[cfg(feature = "ui")]
pub use nonos_clipboard as clipboard;
#[cfg(feature = "ui")]
pub use nonos_browser as browser;
#[cfg(feature = "ui")]
pub use nonos_desktop as desktop;

/// Convenience re-exports (selective).
#[cfg(feature = "ui")]
pub use event::*;
#[cfg(feature = "ui")]
pub use cli::*;
#[cfg(feature = "ui")]
pub use clipboard::*;
#[cfg(feature = "ui")]
pub use browser::*;
#[cfg(feature = "ui")]
pub use desktop::*;

/// Small facade to initialize core UI subsystems. Idempotent.
#[cfg(feature = "ui")]
pub fn init_ui_subsystems() -> Result<(), &'static str> {
    // Event bus first
    nonos_event::init_event_bus();

    // CLI with bounded history
    nonos_cli::init_cli(64);

    // Clipboard
    nonos_clipboard::init_clipboard();

    // Keyboard initialization (driver must be registered separately by platform)
    nonos_keyboard::init_keyboard();

    Ok(())
}

/// Create window helper that delegates into gui_bridge / DesktopManager.
#[cfg(feature = "ui")]
pub fn create_window(title: &str, x: i32, y: i32, width: u32, height: u32) -> Result<u32, &'static str> {
    nonos_gui_bridge::request_create_window(title, x, y, width, height)
}
