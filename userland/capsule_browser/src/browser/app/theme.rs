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
     * as the palette's key is part of what it shows. */
    pub(super) fn retheme(&mut self, out: EventOutcome) -> EventOutcome {
        match self.rethemed() {
            true => EventOutcome::Repaint,
            false => out,
        }
    }

    /* Whether the palette's key moved since the tabs were last marked for
     * it, marking each whole when it did. Under System a theme chosen in
     * Settings arrives with no event, so the tick asks this too. */
    pub(super) fn rethemed(&mut self) -> bool {
        let key = tokens::key();
        if key == self.theme {
            return false;
        }
        self.theme = key;
        for s in self.tabs.list.iter_mut() {
            s.mark(Change::Full);
        }
        true
    }
}
