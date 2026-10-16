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

//! Host proofs for the desktop's pointer path, end to end. A press on a window
//! travels: the input router hit-tests it through the window manager, focuses
//! the window there, arms its press grab and delivers the press in window
//! coordinates; the window manager raises the window and tells the compositor,
//! which restacks its layer; the window's app_skeleton routes the press to its
//! frame, which starts a drag; every motion after that comes back through the
//! press grab, the app moves its layer and its window. Each step is the real
//! source, included under the `crate::` paths its files name each other by.

// The window manager: geometry, the window table (assembled as in wm_proofs,
// whose file this reuses), the z stack and click to focus.
#[path = "../../capsule_wm/src/geometry/mod.rs"]
pub mod geometry;

#[path = "../../wm_proofs/src/window.rs"]
pub mod window;

#[path = "../../capsule_wm/src/z_order/mod.rs"]
pub mod z_order;

#[path = "../../capsule_wm/src/focus/mod.rs"]
pub mod focus;

// The compositor's scene, damage and the submit and raise steps, side by side
// as they sit in its `state` module.
#[path = "../../compositor/src/state/damage.rs"]
pub mod damage;

#[path = "../../compositor/src/state/scene/mod.rs"]
pub mod scene;

#[path = "../../compositor/src/state/scene_raise.rs"]
pub mod scene_raise;

#[path = "../../compositor/src/state/scene_submit.rs"]
pub mod scene_submit;

// The input router's press grab.
#[path = "../../capsule_input_router/src/state/press.rs"]
pub mod press;

// app_skeleton's frame: the drag and the press routing inside a window, under
// `runner` as in app_skeleton, with the event types at `crate::input`.
pub mod input {
    pub use nonos_app_skeleton::{InputEvent, InputKind};
}

// The delivery header magic, at the `crate::wire` path app_skeleton's
// delivery decode names it by.
pub mod wire {
    pub use nonos_app_skeleton::wire::NINP_MAGIC;
}

pub mod runner;

// The toolkit's painting, at the `crate::paint` path app_skeleton's runner
// files name it by.
pub mod paint {
    pub use nonos_toolkit::paint::*;
}

// The desktop shell's tray table, under the `crate::protocol` path its files
// name the label size by. The real code's own style is allowed on the
// include rather than restyled here.
#[path = "../../capsule_desktop_shell/src/protocol/limits.rs"]
pub mod protocol;

#[allow(clippy::new_without_default, clippy::result_unit_err)]
#[path = "../../capsule_desktop_shell/src/state/tray/mod.rs"]
pub mod tray;

#[cfg(test)]
mod tray_share_tests;

// The desktop shell's scale: the brand's rule by the canvas, and its type and
// geometry sizes taken through it.
#[path = "../../capsule_desktop_shell/src/state/scale.rs"]
pub mod shell_scale;

#[path = "../../capsule_desktop_shell/src/render/ui_font.rs"]
pub mod ui_font;

/// How the wheel turns the Launchpad's pages.
#[path = "../../capsule_desktop_shell/src/state/launchpad_wheel.rs"]
pub mod launchpad_wheel;

#[cfg(test)]
mod launchpad_wheel_tests;

#[cfg(test)]
mod shell_scale_tests;
#[cfg(test)]
mod valid_str_tests;

// When the desktop offers the installer: once, on a live session only.
#[path = "../../capsule_desktop_shell/src/state/live_prompt.rs"]
pub mod live_prompt;

#[cfg(test)]
mod live_prompt_tests;

// What the shell holds of the router's grabs while a menu, a dialog, the
// Launchpad, a drag or a rename is up.
#[path = "../../capsule_desktop_shell/src/state/grab_rule.rs"]
pub mod grab_rule;

#[cfg(test)]
mod grab_rule_tests;

// The keys a desktop dialog answers, and which button has the keyboard.
#[path = "../../capsule_desktop_shell/src/state/dialog_keys.rs"]
pub mod dialog_keys;

#[cfg(test)]
mod dialog_keys_tests;

#[cfg(test)]
mod min_size_tests;

// The desktop shell's app table, the one instance-name matcher and the dock's
// window tracking, under the `crate::state` paths the taskbar names them by.
extern crate alloc;

#[path = "../../capsule_desktop_shell/src/state/apps.rs"]
pub mod shell_apps;

#[path = "../../capsule_desktop_shell/src/state/instance.rs"]
pub mod instance;

#[path = "../../capsule_desktop_shell/src/state/taskbar/mod.rs"]
pub mod taskbar;

pub mod state {
    pub use crate::shell_apps as apps;
    pub use crate::shell_apps::DOCK_APPS;
    pub use crate::taskbar::Uptime;
}

#[cfg(test)]
mod instance_tests;

#[cfg(test)]
mod relaunch_tests;

#[cfg(test)]
mod dock_clock_tests;

// The window manager's lifecycle notification as it writes it, and as the
// shell reads it.
#[path = "../../capsule_wm/src/protocol/notify.rs"]
pub mod wm_notify_encode;

#[path = "../../capsule_desktop_shell/src/state/wm_notice.rs"]
pub mod wm_notice;

#[cfg(test)]
mod dock_tests;

// The shell's dock geometry: its panel, and the area a dock repaint commits.
#[path = "."]
pub mod render {
    pub use crate::shadow_reach;
    pub use crate::ui_font;
    #[path = "../../capsule_desktop_shell/src/render/layout.rs"]
    pub mod layout;
}

#[cfg(test)]
mod go_menu_tests;

// Where desktop file actions land, and the question a Delete asks first.
#[path = "../../capsule_desktop_shell/src/server/desktop/home.rs"]
pub mod desktop_home;

#[path = "../../capsule_desktop_shell/src/state/delete_prompt.rs"]
pub mod delete_prompt;

#[cfg(test)]
mod desktop_files_tests;

// Clipboard text into the shell's one-line fields.
#[path = "../../capsule_desktop_shell/src/state/paste_line.rs"]
pub mod paste_line;

#[cfg(test)]
mod paste_line_tests;

// A Launchpad launch the installer is still loading, followed on the shell's
// turns instead of waited out on its frame loop. Its source names `alloc::`
// as no_std code does.
#[path = "../../capsule_desktop_shell/src/state/launch.rs"]
pub mod launch;

#[cfg(test)]
mod launch_tests;

// The apps' shared text input: which key types what into a field, which
// key pastes, and what a pasted line becomes.
#[cfg(test)]
mod text_paste_tests;
#[cfg(test)]
mod text_typed_tests;

// What the shell's toasts say when something did not happen (a launch, a
// package, a desktop file action), and its battery label, which is nothing
// without a reading.
#[path = "../../capsule_desktop_shell/src/state/says.rs"]
pub mod says;

#[path = "../../capsule_desktop_shell/src/state/indicators/battery_text.rs"]
pub mod battery_text;

#[cfg(test)]
mod says_tests;
#[cfg(test)]
mod tray_fit_tests;

// What a Launchpad tool tile hands the Terminal (run, or typed for its
// arguments), kept apart from the paths Open With leaves; and the generated
// table of tool tiles it is decided for.
#[path = "../../capsule_desktop_shell/src/state/open_arg.rs"]
pub mod open_arg;

#[path = "../../capsule_desktop_shell/src/state/tool_apps.rs"]
pub mod tool_apps;

#[cfg(test)]
mod open_arg_tests;

// The menubar's date and time line, 24 and 12 hour.
#[path = "../../capsule_desktop_shell/src/state/indicators/clock.rs"]
pub mod clock_line;

#[cfg(test)]
mod clock_line_tests;

/// What the desktop says about the store vfs loaded, beside the toast levels
/// its file names by `super::NotifyLevel`.
#[path = "."]
pub mod store_state {
    #[path = "../../capsule_desktop_shell/src/state/notify.rs"]
    pub mod notify;
    pub use notify::NotifyLevel;
    #[path = "../../capsule_desktop_shell/src/state/store_word.rs"]
    pub mod store_word;
}

#[cfg(test)]
mod store_word_tests;

// The shell's colours, worked out from the theme's roles, under the module
// names its palette files give each other.
#[path = "."]
pub mod shell_palette {
    #[path = "../../capsule_desktop_shell/src/render/palette/alpha.rs"]
    mod alpha;
    #[path = "../../capsule_desktop_shell/src/render/palette/from_roles.rs"]
    pub mod from_roles;
    #[path = "../../capsule_desktop_shell/src/render/palette/glass.rs"]
    mod glass;
    #[path = "../../capsule_desktop_shell/src/render/palette/prompt.rs"]
    pub mod prompt;
    #[path = "../../capsule_desktop_shell/src/render/palette/table.rs"]
    pub mod table;
}

#[cfg(test)]
mod launchpad_palette_tests;
#[cfg(test)]
mod palette_contrast;
#[cfg(test)]
mod prompt_palette_tests;
#[cfg(test)]
mod shell_palette_tests;

// How long the shell's tick lets a quiet service be (policy, installer), and
// when the tick itself is due on the uptime clock.
#[path = "../../capsule_desktop_shell/src/state/quiet_gap.rs"]
pub mod quiet_gap;
#[path = "../../capsule_desktop_shell/src/server/runner/tick.rs"]
pub mod shell_tick;

#[cfg(test)]
mod quiet_gap_tests;

// How the shell's chrome and desk frames reach their surfaces: drawn off
// screen and copied over after, so a composite never reads half a frame.
#[path = "../../capsule_desktop_shell/src/render/whole_frame.rs"]
pub mod whole_frame;

#[cfg(test)]
mod whole_frame_tests;

// How far a shadowed panel's damage must reach.
#[path = "../../capsule_desktop_shell/src/render/shadow_reach.rs"]
pub mod shadow_reach;

#[cfg(test)]
mod shadow_reach_tests;

// The toast queue, whose generation tells the shell when its chrome frame
// no longer shows the toasts it holds. A toast's tone is marked through
// `crate::sound`, which plays nothing here.
#[path = "."]
pub mod toast_state {
    pub use crate::store_state::NotifyLevel;
    #[path = "../../capsule_desktop_shell/src/state/toast.rs"]
    pub mod toast;
    #[path = "../../capsule_desktop_shell/src/state/toasts.rs"]
    pub mod toasts;
}

pub mod sound {
    pub fn mark(_level: crate::toast_state::NotifyLevel) {}
}

#[cfg(test)]
mod log_line_tests;

#[path = "../../capsule_desktop_shell/src/vfs_client/constants.rs"]
pub mod vfs_constants;

#[cfg(test)]
mod vfs_budget_tests;

#[cfg(test)]
mod patience_tests;
#[cfg(test)]
mod toast_generation_tests;
#[cfg(test)]
mod toast_lifetime_tests;

// What the shell does with the system keys the input router hands it whatever
// has focus: the volume keys' steps, the request they send and the notice they
// put up, and the power key. Beside them, the router's own list of those keys.
#[path = "."]
pub mod shell_system_keys {
    #[path = "../../capsule_desktop_shell/src/state/volume.rs"]
    pub mod volume;
    #[path = "../../capsule_desktop_shell/src/state/system_key.rs"]
    pub mod system_key;
}

#[path = "../../capsule_input_router/src/route/shell_keys.rs"]
pub mod router_shell_keys;

#[cfg(test)]
mod system_key_tests;
