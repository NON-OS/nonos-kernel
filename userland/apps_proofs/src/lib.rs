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

//! Host proofs for what the desktop apps say when a service is missing, a list
//! comes back empty or an input is too large. Each app keeps that decision in a
//! small file of its own, away from its drawing and IPC code, and the file is
//! included here by `#[path]`, so these tests pin the source the capsule builds
//! rather than a copy of it. Apps with a proofs crate of their own (the file
//! manager, the editor, settings) are proven there instead.

extern crate alloc;

/// The calculator's arithmetic, why it stops and how it shows numbers and
/// errors, and its keypad: the window state, every button and the actions they
/// run, the key map and the History page's geometry, under `calc` as in the
/// capsule so the files' `crate::calc::` and `super::` paths resolve. Only the
/// painting and the skeleton glue are left out.
#[path = "."]
pub mod calc {
    #[path = "../../capsule_calculator/src/calc/actions/mod.rs"]
    pub mod actions;
    #[path = "../../capsule_calculator/src/calc/buttons/mod.rs"]
    pub mod buttons;
    #[path = "../../capsule_calculator/src/calc/convert/mod.rs"]
    pub mod convert;
    #[path = "../../capsule_calculator/src/calc/error_kind.rs"]
    pub mod error_kind;
    #[path = "../../capsule_calculator/src/calc/fixed.rs"]
    pub mod fixed;
    #[path = "../../capsule_calculator/src/calc/format/mod.rs"]
    pub mod format;
    #[path = "../../capsule_calculator/src/calc/history/mod.rs"]
    pub mod history;
    #[path = "../../capsule_calculator/src/calc/hit.rs"]
    pub mod hit;
    #[path = "../../capsule_calculator/src/calc/manifest.rs"]
    pub mod manifest;
    #[path = "../../capsule_calculator/src/calc/mode.rs"]
    pub mod mode;
    #[path = "../../capsule_calculator/src/calc/op.rs"]
    pub mod op;
    #[path = "../../capsule_calculator/src/calc/paste.rs"]
    pub mod paste;
    #[path = "../../capsule_calculator/src/calc/prog/mod.rs"]
    pub mod prog;
    #[path = "../../capsule_calculator/src/calc/sci/mod.rs"]
    pub mod sci;
    #[path = "../../capsule_calculator/src/calc/state/mod.rs"]
    pub mod state;
    #[path = "../../capsule_calculator/src/calc/unary.rs"]
    pub mod unary;
    #[path = "."]
    pub mod event {
        #[path = "../../capsule_calculator/src/calc/event/key_classifier.rs"]
        pub mod key_classifier;
    }
    #[path = "."]
    pub mod ui {
        #[path = "../../capsule_calculator/src/calc/ui/convert_geom.rs"]
        pub mod convert_geom;
        #[path = "../../capsule_calculator/src/calc/ui/convert_hit.rs"]
        pub mod convert_hit;
        #[path = "../../capsule_calculator/src/calc/ui/history_geom.rs"]
        pub mod history_geom;
        #[path = "../../capsule_calculator/src/calc/ui/metrics.rs"]
        pub mod metrics;
    }
}

/// The clock's calendar arithmetic and what it says when the system clock
/// cannot be read or set.
#[path = "../../capsule_clock/src/clock/civil.rs"]
pub mod clock_civil;
#[path = "../../capsule_clock/src/clock/says.rs"]
pub mod clock_says;
#[path = "../../capsule_clock/src/clock/stopwatch.rs"]
pub mod clock_stopwatch;
#[path = "../../capsule_clock/src/clock/timer.rs"]
pub mod clock_timer;

/// What the image viewer says when it has no image to show, and the largest
/// file and image it takes in.
#[path = "../../capsule_image_viewer/src/viewer/budget.rs"]
pub mod image_budget;
#[path = "../../capsule_image_viewer/src/viewer/says.rs"]
pub mod image_says;

/// What the image viewer's overlays say, where its gallery scrolls and which
/// thumbnails it keeps, its prev and next buttons, and how often it asks the
/// shell for a file. Mounted as `viewer` at the root so the files'
/// `crate::viewer::` paths resolve.
#[path = "."]
pub mod viewer {
    #[path = "../../capsule_image_viewer/src/viewer/arg_cadence.rs"]
    pub mod arg_cadence;
    #[path = "../../capsule_image_viewer/src/viewer/caption.rs"]
    pub mod caption;
    #[path = "../../capsule_image_viewer/src/viewer/nav.rs"]
    pub mod nav;
    #[path = "../../capsule_image_viewer/src/viewer/viewport.rs"]
    pub mod viewport;
    #[path = "."]
    pub mod gallery {
        #[path = "../../capsule_image_viewer/src/viewer/gallery/layout.rs"]
        pub mod layout;
    }
}

/// Whether the markdown viewer lays out what it read from /readme.txt. Its
/// parser's side (a blank file parses to no blocks) is proven with the parser
/// in capsule_mdview/layout_tests.
#[path = "../../capsule_mdview/src/mdview/verdict.rs"]
pub mod mdview_verdict;

/// Where the markdown viewer's lines sit and how far its wheel scrolls the
/// page, over the viewer's own line metrics. Mounted with a `layout` that
/// names what the capsule's does, so the file's `super::layout` resolves.
#[path = "."]
pub mod mdview_page {
    #[path = "."]
    pub mod layout {
        #[path = "../../capsule_mdview/src/mdview/layout/block.rs"]
        pub mod block;
        #[path = "../../capsule_mdview/src/mdview/layout/metrics.rs"]
        pub mod metrics;
        pub use block::{Line, Span, Style};
        pub use metrics::{gap, line_height};
    }
    #[path = "../../capsule_mdview/src/mdview/scroll.rs"]
    pub mod scroll;
}

/// Why the video library is empty when its folders were never read.
#[path = "../../capsule_video_player/src/catalog/says.rs"]
pub mod video_says;

/// What the video library lists (only what the player decodes), the folders
/// it reads, and its search and folder filter. Mounted as `catalog` at the
/// root so the files' `crate::catalog::` paths resolve.
#[path = "."]
pub mod catalog {
    #[path = "../../capsule_video_player/src/catalog/entry.rs"]
    pub mod entry;
    #[path = "../../capsule_video_player/src/catalog/folders.rs"]
    pub mod folders;
    #[path = "../../capsule_video_player/src/catalog/kind.rs"]
    pub mod kind;
    #[path = "../../capsule_video_player/src/catalog/media.rs"]
    pub mod media;
}
#[path = "../../capsule_video_player/src/app/browse.rs"]
pub mod video_browse;
/// When the video player asks for its window full screen.
#[path = "../../capsule_video_player/src/app/full_screen.rs"]
pub mod video_full_screen;
#[path = "../../capsule_video_player/src/app/open_arg_reply.rs"]
pub mod video_open_arg;

/// The video player's key map on its list pages, where printable keys type
/// into the search. `action.rs` names `crate::ui::screen::Route`.
#[path = "."]
pub mod video_event {
    #[path = "../../capsule_video_player/src/event/action.rs"]
    pub mod action;
    #[path = "../../capsule_video_player/src/event/key.rs"]
    pub mod key;
}
/// The video player's routes, and where its list starts so the selection
/// stays in sight.
#[path = "."]
pub mod ui {
    #[path = "../../capsule_video_player/src/ui/rows.rs"]
    pub mod rows;
    #[path = "../../capsule_video_player/src/ui/screen.rs"]
    pub mod screen;
}

/// The process monitor's table and status-strip notes.
#[path = "../../capsule_process_manager/src/pm/state/notes.rs"]
pub mod pm_notes;

/// Which processes the process monitor will not end, and its percent text.
#[path = "../../capsule_process_manager/src/pm/critical.rs"]
pub mod pm_critical;
#[path = "../../capsule_process_manager/src/pm/format.rs"]
pub mod pm_format;

/// A pasted line into the process monitor's search field.
#[path = "../../capsule_process_manager/src/pm/state/query_paste.rs"]
pub mod pm_query_paste;

/// The audio player's transport (its play, pause and feed state machine) and
/// what the window says when it cannot play. The transport names its decoder,
/// resampler and debug marker by `crate::` paths, so those are mounted at this
/// crate's root under the same names; the marker is a no-op here. `#[path = "."]`
/// keeps the inline modules' includes relative to this directory, which has no
/// `decode/` or `transport/` of its own.
#[path = "../../capsule_audio_player/src/trouble.rs"]
pub mod audio_trouble;

#[path = "."]
pub mod decode {
    #[path = "../../capsule_audio_player/src/decode/decoder.rs"]
    mod decoder;
    #[path = "../../capsule_audio_player/src/decode/mp3_index.rs"]
    pub mod mp3_index;
    #[path = "../../capsule_audio_player/src/decode/wav.rs"]
    pub mod wav;
    #[path = "../../capsule_audio_player/src/decode/wav_pcm.rs"]
    mod wav_pcm;
    pub use decoder::{AudioInfo, Decoder};
}

/// The audio player's waveform bars, built as a track decodes, and the largest
/// track it reads whole.
#[path = "../../capsule_audio_player/src/peaks.rs"]
pub mod peaks;
#[path = "../../capsule_audio_player/src/track_limit.rs"]
pub mod track_limit;
/// The format label Now Playing shows for the loaded track.
#[path = "../../capsule_audio_player/src/track_fmt.rs"]
pub mod track_fmt;

pub mod mark {
    pub fn mark(_line: &str) {}
}

/// Which files the audio player's library lists (only what its decoder opens),
/// the order of its "By format" tab and what it does with a file the desktop
/// shell hands it, under `library` as in the capsule so `super::track`
/// resolves.
#[path = "."]
pub mod library {
    #[path = "../../capsule_audio_player/src/library/handed.rs"]
    pub mod handed;
    #[path = "../../capsule_audio_player/src/library/order.rs"]
    pub mod order;
    #[path = "../../capsule_audio_player/src/library/playable.rs"]
    pub mod playable;
    #[path = "../../capsule_audio_player/src/library/rescan_gap.rs"]
    pub mod rescan_gap;
    #[path = "../../capsule_audio_player/src/library/track.rs"]
    pub mod track;
}

#[path = "../../capsule_audio_player/src/resample.rs"]
pub mod resample;

#[path = "."]
pub mod transport {
    #[path = "../../capsule_audio_player/src/transport/defs.rs"]
    pub mod defs;
    #[path = "../../capsule_audio_player/src/transport/machine.rs"]
    pub mod machine;
    #[path = "../../capsule_audio_player/src/transport/pump.rs"]
    pub mod pump;
}

#[cfg(test)]
mod audio_format_tests;
#[cfg(test)]
mod audio_library_tests;
#[cfg(test)]
mod audio_load_tests;
#[cfg(test)]
mod audio_open_tests;
#[cfg(test)]
mod audio_tests;
#[cfg(test)]
mod calc_convert_tests;
#[cfg(test)]
mod calc_keypad_tests;
#[cfg(test)]
mod calc_tests;
#[cfg(test)]
mod calc_paste_tests;
#[cfg(test)]
mod clock_span_tests;
#[cfg(test)]
mod clock_tests;
#[cfg(test)]
mod image_arg_tests;
#[cfg(test)]
mod image_tests;
#[cfg(test)]
mod image_view_tests;
#[cfg(test)]
mod mdview_tests;
#[cfg(test)]
mod mdview_wheel_tests;
#[cfg(test)]
mod pm_paste_tests;
#[cfg(test)]
mod pm_tests;
#[cfg(test)]
mod video_browse_tests;
#[cfg(test)]
mod video_full_screen_tests;
#[cfg(test)]
mod video_scroll_tests;
#[cfg(test)]
mod video_tests;
#[cfg(test)]
mod wheel_tests;

/// How the process monitor shares its width between the sidebar, the screen
/// and the inspector. fit.rs names `crate::pm::state::Screen` and
/// `super::metrics`, so both are given those names here.
#[path = "../../capsule_process_manager/src/pm/state/screen.rs"]
pub mod pm_screen;
#[path = "../../capsule_process_manager/src/pm/ui/metrics.rs"]
pub mod metrics;
#[path = "../../capsule_process_manager/src/pm/ui/fit.rs"]
pub mod pm_fit;
pub mod pm {
    pub mod state {
        pub use crate::pm_screen::Screen;
    }
}

#[cfg(test)]
mod pm_fit_tests;

/// The audio player's load, read and decoded a tick at a time.
#[path = "../../capsule_audio_player/src/loading.rs"]
pub mod loading;

/// Where the audio player's right rail puts its parts, and which track a click
/// on its queue means, on the player's own geometry and type scale.
#[path = "."]
pub mod audio_ui {
    #[path = "../../capsule_audio_player/src/ui/geometry.rs"]
    pub mod geometry;
    #[path = "../../capsule_audio_player/src/ui/metrics.rs"]
    pub mod metrics;
    #[path = "."]
    pub mod shell {
        #[path = "../../capsule_audio_player/src/ui/shell/ground.rs"]
        pub mod ground;
        #[path = "../../capsule_audio_player/src/ui/shell/rail_geom.rs"]
        pub mod rail_geom;
    }
    #[path = "../../capsule_audio_player/src/ui/search_key.rs"]
    pub mod search_key;
}

/// What a file Music downloads is called in /home/nonos/music.
#[path = "../../capsule_audio_player/src/fetch/name.rs"]
pub mod audio_fetch_name;

#[cfg(test)]
mod audio_fetch_tests;

/// The player's volume controls as the system's master volume.
#[path = "../../capsule_audio_player/src/volume.rs"]
pub mod audio_volume;

/// The player's keys away from the Search field.
#[path = "../../capsule_audio_player/src/ui/shortcut.rs"]
pub mod audio_shortcut;

#[cfg(test)]
mod audio_keys_tests;

/// The Downloads page: its list and what each row says. row_text.rs reads
/// `super::list`, so both sit in one module as they do in `fetch`.
#[path = "."]
pub mod audio_downloads {
    #[path = "../../capsule_audio_player/src/fetch/list.rs"]
    pub mod list;
    #[path = "../../capsule_audio_player/src/fetch/row_text.rs"]
    pub mod row_text;
}

/// Where the cover art's grid motif draws its floor lines.
#[path = "../../capsule_audio_player/src/ui/art/rungs.rs"]
pub mod audio_rungs;

#[cfg(test)]
mod audio_downloads_tests;

/// What Music reads from a file's tags, and how it groups a library.
#[path = "../../capsule_audio_player/src/library/tags/mod.rs"]
pub mod audio_tags;

#[cfg(test)]
mod audio_tags_tests;

#[cfg(test)]
mod audio_rail_tests;
#[cfg(test)]
mod audio_ground_tests;
#[cfg(test)]
mod audio_step_tests;
#[cfg(test)]
mod audio_stream_tests;
#[cfg(test)]
mod audio_time_tests;

/// Snake: the day's run the home card names and a click sets up, what a click
/// on a rules switch changes, and what the Ranks screen says became of the
/// ranks on disk. Mounted as one module so the files' `super::` paths resolve.
#[path = "."]
pub mod snake_state {
    #[path = "../../capsule_snake/src/snake/state/daily.rs"]
    pub mod daily;
    #[path = "../../capsule_snake/src/snake/state/difficulty.rs"]
    pub mod difficulty;
    #[path = "../../capsule_snake/src/snake/state/kept.rs"]
    pub mod kept;
    #[path = "../../capsule_snake/src/snake/state/mode.rs"]
    pub mod mode;
    #[path = "../../capsule_snake/src/snake/state/mode_text.rs"]
    pub mod mode_text;
    #[path = "../../capsule_snake/src/snake/state/options.rs"]
    pub mod options;
}

#[cfg(test)]
mod snake_tests;

/// About: the Overview badge read from how the kernel admitted the window,
/// the capability count from the word the kernel holds for it, and the
/// Display screen's present path. Mounted as About's `data` so the files'
/// `super::` paths resolve.
#[path = "."]
pub mod about_data {
    #[path = "../../capsule_about/src/about/data/admission.rs"]
    pub mod admission;
    #[path = "../../capsule_about/src/about/data/caps.rs"]
    pub mod caps;
    #[path = "../../capsule_about/src/about/data/own_caps.rs"]
    pub mod own_caps;
    #[path = "../../capsule_about/src/about/data/present.rs"]
    pub mod present;
    #[path = "../../capsule_about/src/about/data/trust.rs"]
    pub mod trust;
}

#[cfg(test)]
mod about_tests;

/// Where About's wheel takes the screen on show, on About's own step.
/// Mounted with `ui::metrics` so the file's `super::` path resolves.
#[path = "."]
pub mod about_scroll {
    #[path = "../../capsule_about/src/about/scroll_wheel.rs"]
    pub mod scroll_wheel;
    #[path = "."]
    pub mod ui {
        #[path = "../../capsule_about/src/about/ui/metrics.rs"]
        pub mod metrics;
    }
}

#[cfg(test)]
mod about_wheel_tests;
