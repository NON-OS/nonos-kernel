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

pub(super) fn spawn() {
    spawn_text_editor();
    spawn_settings();
    spawn_process_manager();
}

#[cfg(feature = "nonos-capsule-text-editor")]
fn spawn_text_editor() {
    use crate::userspace::capsule_text_editor as c;
    super::boot::capsule(
        "APP-TEXT-EDITOR",
        "app_text_editor",
        c::spawn_text_editor_capsule,
        c::shared_state,
    );
}
#[cfg(not(feature = "nonos-capsule-text-editor"))]
fn spawn_text_editor() {}

#[cfg(feature = "nonos-capsule-settings")]
fn spawn_settings() {
    use crate::userspace::capsule_settings as c;
    super::boot::capsule(
        "APP-SETTINGS",
        "app_settings",
        c::spawn_settings_capsule,
        c::shared_state,
    );
}
#[cfg(not(feature = "nonos-capsule-settings"))]
fn spawn_settings() {}

#[cfg(feature = "nonos-capsule-process-manager")]
fn spawn_process_manager() {
    use crate::userspace::capsule_process_manager as c;
    super::boot::capsule(
        "APP-PROCESS-MANAGER",
        "app_process_manager",
        c::spawn_process_manager_capsule,
        c::shared_state,
    );
}
#[cfg(not(feature = "nonos-capsule-process-manager"))]
fn spawn_process_manager() {}
