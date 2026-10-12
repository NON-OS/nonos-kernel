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

use alloc::string::String;
use alloc::vec::Vec;

use crate::browser::paint::start::shortcut_data::SHORTCUTS;
use crate::browser::paint::tokens::TILES;
use crate::browser::shell::{site_label, Shell};
use crate::browser::ui::start_geom::MAX_FAVS;

/// One start-page favourite: what the tile says, where it goes, its colour.
pub struct Fav {
    pub label: String,
    pub url: String,
    pub letter: char,
    pub color: u32,
}

/// The tile colour `key` always gets.
pub fn tile_color(key: &str) -> u32 {
    let hash = key.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    TILES[hash as usize % TILES.len()]
}

/// The letter on `host`'s tile: its first letter or digit past a leading
/// `www.`, upper case.
pub fn tile_letter(host: &str) -> char {
    let name = host.strip_prefix("www.").filter(|rest| !rest.is_empty()).unwrap_or(host);
    name.chars().find(|c| c.is_alphanumeric()).unwrap_or('?').to_ascii_uppercase()
}

fn fav(label: &str, url: &str, host: &str) -> Fav {
    Fav {
        label: String::from(label),
        url: String::from(url),
        letter: tile_letter(host),
        color: tile_color(host),
    }
}

/// Bookmarks first, then the built-in shortcuts not already bookmarked, up
/// to the tiles the start page has room for.
pub fn favourites(shell: &Shell) -> Vec<Fav> {
    let mut out: Vec<Fav> = shell
        .bookmarks
        .iter()
        .map(|b| fav(&site_label::title(&b.title, &b.url), &b.url, &site_label::site(&b.url)))
        .take(MAX_FAVS)
        .collect();
    for s in SHORTCUTS.iter() {
        if out.len() >= MAX_FAVS || out.iter().any(|f| f.url == s.url) {
            continue;
        }
        out.push(fav(s.label, s.url, s.label));
    }
    out
}
