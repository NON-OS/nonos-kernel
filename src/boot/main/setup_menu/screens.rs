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

extern crate alloc;
use super::{brand, input::*, render, state::*};
use crate::graphics::framebuffer;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Screen {
    Welcome,
    Language,
    Wallpaper,
    Crypto,
    Complete,
}
static SEL: AtomicUsize = AtomicUsize::new(0);

pub(super) fn render_and_handle(cfg: &mut SetupConfig, scr: Screen) -> Screen {
    render::clear();
    let (_, h) = framebuffer::dimensions();
    let s = SEL.load(Ordering::Relaxed);
    match scr {
        Screen::Welcome => {
            render::logo(h / 6);
            render::text_centered(brand::TAGLINE, (h / 6 + 100) as i32, brand::TEXT_SECONDARY);
            render::text_centered("Welcome to NONOS", (h / 2) as i32, brand::TEXT_PRIMARY);
            render::text_centered(
                "Press ENTER to begin",
                (h / 2 + 30) as i32,
                brand::TEXT_SECONDARY,
            );
            render::progress_dots(h - 80, 0, 4);
            render::footer("[Enter] Continue", brand::VERSION);
        }
        Screen::Language => list(
            "Select Language",
            &LANGUAGES.iter().map(|x| x.1).collect::<alloc::vec::Vec<_>>(),
            s,
            cfg.language_index,
            h,
            1,
        ),
        Screen::Wallpaper => list(
            "Choose Wallpaper",
            &WALLPAPERS.to_vec(),
            s,
            cfg.wallpaper_index.unwrap_or(99),
            h,
            2,
        ),
        Screen::Crypto => {
            render::text_centered("Security Configuration", 50, brand::TEXT_PRIMARY);
            render::checkbox(200, 120, "Generate Keys (Ed25519/X25519)", cfg.generate_keys, s == 0);
            render::checkbox(200, 155, "Hardware Crypto (AES-NI)", cfg.hardware_crypto, s == 1);
            render::checkbox(200, 190, "ZK Attestation (Groth16)", cfg.zk_attestation, s == 2);
            render::checkbox(200, 225, "Developer Mode", cfg.developer_mode, s == 3);
            render::menu_item(200, h - 100, 400, ">> Finish Setup", s == 4);
            render::progress_dots(h - 80, 3, 4);
            render::footer("[Space] Toggle", "[Q] Back");
        }
        Screen::Complete => return Screen::Complete,
    }
    input(cfg, scr, s)
}

fn list(t: &str, items: &[&str], s: usize, c: usize, h: u32, step: usize) {
    render::text_centered(t, 50, brand::TEXT_PRIMARY);
    for (i, n) in items.iter().enumerate() {
        render::menu_item(
            200,
            100 + i as u32 * 35,
            400,
            &if i == c { alloc::format!("{} *", n) } else { (*n).into() },
            i == s,
        );
    }
    render::progress_dots(h - 80, step, 4);
    render::footer("[Up/Down] Navigate  [Enter] Select", "[Q] Back");
}

fn input(cfg: &mut SetupConfig, scr: Screen, s: usize) -> Screen {
    let max = match scr {
        Screen::Language => LANGUAGES.len() - 1,
        Screen::Wallpaper => WALLPAPERS.len() - 1,
        Screen::Crypto => 4,
        _ => 0,
    };
    match poll_menu_input() {
        MenuAction::Up if s > 0 => {
            SEL.store(s - 1, Ordering::Relaxed);
            scr
        }
        MenuAction::Down if s < max => {
            SEL.store(s + 1, Ordering::Relaxed);
            scr
        }
        MenuAction::Select => {
            SEL.store(0, Ordering::Relaxed);
            sel(cfg, scr, s)
        }
        MenuAction::Back => {
            SEL.store(0, Ordering::Relaxed);
            match scr {
                Screen::Language => Screen::Welcome,
                Screen::Wallpaper => Screen::Language,
                Screen::Crypto => Screen::Wallpaper,
                x => x,
            }
        }
        MenuAction::Skip => {
            SEL.store(0, Ordering::Relaxed);
            match scr {
                Screen::Welcome | Screen::Crypto => Screen::Complete,
                Screen::Language => Screen::Wallpaper,
                Screen::Wallpaper => Screen::Crypto,
                x => x,
            }
        }
        _ => scr,
    }
}

fn sel(cfg: &mut SetupConfig, scr: Screen, s: usize) -> Screen {
    match scr {
        Screen::Welcome => Screen::Language,
        Screen::Language => {
            cfg.language_index = s;
            Screen::Wallpaper
        }
        Screen::Wallpaper => {
            cfg.wallpaper_index = Some(s);
            Screen::Crypto
        }
        Screen::Crypto if s == 4 => Screen::Complete,
        Screen::Crypto => {
            match s {
                0 => cfg.generate_keys = !cfg.generate_keys,
                1 => cfg.hardware_crypto = !cfg.hardware_crypto,
                2 => cfg.zk_attestation = !cfg.zk_attestation,
                3 => cfg.developer_mode = !cfg.developer_mode,
                _ => {}
            };
            SEL.store(s, Ordering::Relaxed);
            Screen::Crypto
        }
        x => x,
    }
}
