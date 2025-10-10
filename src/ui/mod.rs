//! User Interface subsystem for NON-OS kernel

pub mod browser;
pub mod cli;
pub mod clipboard;
pub mod event;
pub mod gui_bridge;
pub mod keyboard;
pub mod menu;      // menu panel
//pub mod sysinfo;   // NEW: pretty System Info overlay
pub mod tui;

pub use browser::*;
pub use cli::*;
pub use clipboard::*;
pub use event::*;
// (menu/sysinfo are imported explicitly where used)
