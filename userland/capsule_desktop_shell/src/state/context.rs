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

use super::{MenubarState, PkgInstallPrompt, TaskbarState, ToastQueue, TrayTable};

pub struct Context {
    pub compositor_port: u32,
    pub wm_port: u32,
    pub input_router_port: u32,
    /// The wallpaper service's port, 0 until it registers.
    pub wallpaper_port: u32,
    /// Whether the wallpaper has taken the desktop's scaling yet
    /// (server/wallpaper_policy.rs).
    pub wallpaper_policy_sent: bool,
    pub input_kind_mask: u32,
    pub input_ready: bool,
    pub wm_notify_ready: bool,
    pub width: u32,
    pub height: u32,
    /// Drawing pixels per logical pixel, in quarters (`state::scale`).
    pub scale: u32,
    pub stride: u32,
    /// The surface every painter draws on. It is the chrome surface, over
    /// the windows, except while the desktop's icons are painted onto the
    /// desk surface under them (render/chrome.rs paint_desk).
    pub backing_va: u64,
    /// The shell's two surfaces, both the size of the display: the desk in
    /// the compositor's band under every application window, with the
    /// desktop's icons, and the chrome in the band over every window, with
    /// the menubar, the dock, menus, the Launchpad, toasts and dialogs.
    pub desk_va: u64,
    pub chrome_va: u64,
    /// The off-screen frame each surface's paint is drawn in before it is
    /// copied over the surface (render/whole_frame.rs), kept between paints.
    pub back: alloc::vec::Vec<u32>,
    /// The router grab mask the shell holds (state/grab_rule.rs).
    pub grab_held: u32,
    pub tray: TrayTable,
    pub taskbar: TaskbarState,
    /// Whether the full-screen Launchpad overlay is open.
    pub launchpad: bool,
    pub launchpad_query: alloc::string::String,
    pub launchpad_page: usize,
    /// Wheel notches added up toward the next page turn.
    pub launchpad_wheel: crate::state::launchpad_wheel::PageWheel,
    pub launchpad_view: alloc::vec::Vec<crate::render::launchpad::Target>,
    pub toasts: ToastQueue,
    pub toast_layer_live: bool,
    /// The toast queue's generation the chrome was last painted with.
    pub toasts_drawn: u32,
    /// The toast queue's generation the panel was last brought on screen
    /// with (render/toasts.rs sync_toast_layer). The serve loop syncs the
    /// panel whenever the queue moved past it, whoever pushed or expired.
    pub toasts_synced: u32,
    /// The panel the shell holds a window over for its toasts, as last
    /// opened with the window manager (render/toasts.rs claim_presses).
    pub toast_window: Option<(u32, u32, u32, u32)>,
    /// Whether the DHCP client held an address at the last tick: the menu
    /// bar's network glyph, and the edge the "network connected" toast is on.
    pub net_was_online: bool,
    pub clock_24h: bool,
    // Whole hours east of UTC, from the Timezone setting.
    pub tz_hours: i8,
    pub policy_port: u32,
    /// When the tick may next read the policy store, after one went
    /// unanswered (state/quiet_gap.rs).
    pub policy_gap: crate::state::quiet_gap::QuietGap,
    /// When the tick may next ask the installer for its apps, likewise.
    pub installer_gap: crate::state::quiet_gap::QuietGap,
    pub next_request_id: u32,
    /// Entries at the VFS root, shown as icons on the desktop. Loaded lazily
    /// once the vfs_pool service is up, then refreshed after we mutate it.
    pub desktop_items: alloc::vec::Vec<crate::vfs_client::Entry>,
    /// Base names of the capsule-store apps the installer reports, already
    /// filtered of anything impersonating a built-in. Loaded lazily once the
    /// installer service is up, then left alone.
    pub installed_apps: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    pub installed_apps_loaded: bool,
    /// File names of the `.nonos` packages sitting in /pkgs, rescanned every
    /// tick so one dropped in after boot appears without a restart.
    pub pkg_files: alloc::vec::Vec<alloc::string::String>,
    pub pkg_files_loaded: bool,
    /// Pid the installer handed back for each store app we have launched, so a
    /// second click focuses that window instead of loading another copy. An
    /// entry is dropped once its pid stops accepting control frames.
    pub installed_pids: alloc::collections::BTreeMap<alloc::vec::Vec<u8>, u32>,
    /// The Launchpad launch the installer is still loading, followed on the
    /// shell's turns (`server/handlers/installed_launch_poll.rs`).
    pub launch: Option<crate::state::launch::Launch>,
    /// Which menu-bar title is open, and the row under the pointer inside it.
    pub menubar: MenubarState,
    /// Top-left corner of the desktop right-click menu, or None when hidden.
    pub desktop_menu: Option<(u32, u32)>,
    /// Which menu row the pointer is over, so it can be highlighted.
    pub menu_hover: Option<usize>,
    /// The desktop item the open menu acts on; None means the empty-desktop
    /// menu (New Folder / New File) rather than the per-item one.
    pub menu_target: Option<usize>,
    /// The item being renamed and its edit buffer, while an inline rename is in
    /// progress.
    pub rename: Option<usize>,
    pub rename_buf: alloc::string::String,
    /// Drag-to-move: the icon a left-press started on, whether the pointer has
    /// moved far enough to count as a drag, and the current pointer position so
    /// the dragged icon can follow the cursor.
    pub drag_from: Option<usize>,
    pub drag_moved: bool,
    pub drag_x: u32,
    pub drag_y: u32,
    /// Open-with broker: path handed to a target app's service name by
    /// `OP_OPEN_WITH`, pulled once via `OP_TAKE_OPEN_ARG` after the app wakes.
    pub pending_open: alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
    /// A command line a Launchpad tool tile left for the Terminal, answered
    /// only to a Terminal window and only while still wanted
    /// (state::open_arg). Kept apart from `pending_open`, which any process
    /// can fill through `OP_OPEN_WITH`.
    pub pending_command: Option<crate::state::open_arg::PendingCommand>,
    /// Name of the runtime-installed app whose launch is awaiting the consent
    /// modal, or None when no dialog is up.
    pub pending_consent: Option<alloc::vec::Vec<u8>>,
    /// The /pkgs package whose install awaits the consent modal, carrying the
    /// summary pkg_query returned, or None when no dialog is up.
    pub pending_pkg_install: Option<PkgInstallPrompt>,
    /// The offer to install NONOS, shown once at the start of a live session.
    pub live_prompt: crate::state::live_prompt::LivePrompt,
    /// A desktop Delete waiting on its confirmation.
    pub pending_delete: crate::state::delete_prompt::DeletePrompt,
    /// Which of the open dialog's two buttons the keyboard is on.
    pub dialog_focus: crate::state::dialog_keys::DialogFocus,
    /// The colours the shell paints with, worked out from the theme at the
    /// start of every paint (render/chrome.rs paint_chrome).
    pub palette: crate::render::palette::ShellPalette,
}

impl Context {
    pub fn issue_request_id(&mut self) -> u32 {
        let id = self.next_request_id;
        self.next_request_id = id.wrapping_add(1).max(1);
        id
    }
}
