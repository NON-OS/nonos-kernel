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

use nonos_app_skeleton::EventOutcome;

use super::browser::Browser;
use crate::browser::omnibox::Change;
use crate::browser::paint::tokens;

impl Browser {
    /* An event that switched the appearance changed every tab's chrome, so
     * each is marked whole: the tab in view repaints under the new palette
     * now, and any other when it is shown. The strip follows on its own,
     * as the appearance is part of what it shows. */
    pub(super) fn retheme(&mut self, was_dark: bool, out: EventOutcome) -> EventOutcome {
        if tokens::is_dark() == was_dark {
            return out;
        }
        for s in self.tabs.list.iter_mut() {
            s.mark(Change::Full);
        }
        EventOutcome::Repaint
    }
}
