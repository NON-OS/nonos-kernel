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

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind, KEY_BACKSPACE, KEY_ENTER, KEY_ESC};

use crate::browser::omnibox::text_char;
use crate::browser::shell::groups::MAX_NAME;
use crate::browser::shell::Shell;
use crate::browser::tab_groups;

/// A key while a group is being renamed: Enter keeps the name, Esc drops
/// it, Backspace and typed characters edit it, and every other key is held
/// back from the page and the address pill. None when no rename is open.
pub(super) fn rename_key(shell: &mut Shell, event: &InputEvent) -> Option<EventOutcome> {
    if event.kind != InputKind::KeyDown {
        return None;
    }
    let buf = shell.rename.as_mut()?;
    match event.code {
        KEY_ENTER => tab_groups::commit_rename(shell),
        KEY_ESC => shell.rename = None,
        KEY_BACKSPACE => {
            buf.pop();
        }
        code => match text_char(code, event.flags) {
            Some(c) if buf.chars().count() < MAX_NAME => buf.push(c),
            _ => return Some(EventOutcome::Idle),
        },
    }
    Some(EventOutcome::Repaint)
}
