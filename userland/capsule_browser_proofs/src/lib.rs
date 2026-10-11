// NONOS Operating System (AGPL-3.0-or-later)
/* The engine source compiled here is held to the capsule crate own clippy
 * gate, not this one. Vendoring it under -D warnings would make a lint in a
 * file this crate does not own fail the proof run, so the three that reach
 * across the boundary are allowed here and nowhere else. */
#![allow(clippy::redundant_closure, clippy::manual_is_multiple_of, clippy::too_many_arguments)]
//! Host proofs for the browser engine: its real source is included by #[path]
//! under a tree mirroring the capsule's paths, so the files compile unchanged.
extern crate alloc;

pub mod browser;
pub mod grid_page;
pub mod probe;
pub mod render;

mod band_tests;
mod atom_clip_tests;
mod blit_tests;
mod bookmark_tests;
mod block_in_inline_tests;
mod canvas_tests;
mod cascade_proofs;
mod cascade_tests;
mod chrome_hit_tests;
mod chunked_tests;
mod classify_tests;
mod clock_tests;
mod codec_damage_tests;
mod codec_fixture;
mod codec_tests;
#[cfg(test)]
mod clone_tests;
mod color_fonts_images;
mod color_tests;
mod computed_style_tests;
#[cfg(test)]
mod cookie_tests;
mod css_utf8_tests;
mod damage_tests;
mod dl_name_tests;
mod downloads_tests;
#[cfg(test)]
mod dom_tests;
mod edit_key_tests;
#[cfg(test)]
mod entity_tests;
mod fallback_tests;
mod fetch_proofs;
mod fit_tests;
mod float_tests;
mod focus_tests;
mod fx_tests;
mod grid_auto_tests;
mod grid_clip_tests;
mod grid_tests;
mod group_name_tests;
mod groups_tests;
mod gzip_tests;
mod history_tests;
mod hit_screen_tests;
mod hostile_geom_tests;
#[cfg(test)]
mod inline_style_tests;
mod label_tests;
mod layout_tests;
#[cfg(test)]
mod line_edit_tests;
mod keyword_tests;
mod link_tests;
mod marker_tests;
#[cfg(test)]
mod media_query_tests;
mod merge_groups_tests;
mod merge_tests;
mod bg_layer_tests;
mod filter_tests;
mod mask_tests;
mod math_len_tests;
mod replaced_clamp_tests;
mod narrow_tests;
mod pos_tests;
mod quirks_table_tests;
mod reader_column_tests;
mod reader_meta_tests;
mod reader_tests;
mod reader_ui_tests;
mod recv_pending_tests;
mod round2_tests;
mod route_tests;
mod round_clip_tests;
#[cfg(test)]
mod script_plan_tests;
mod scroll_tests;
mod selector_tests;
mod shell_tests;
mod sibling_tests;
mod sidebar_groups_tests;
mod sidebar_mode_tests;
mod sidebar_parts_tests;
mod sidebar_tests;
mod start_geom_tests;
mod svg_paint_tests;
mod table_pct_tests;
mod table_tests;
mod tab_turn_tests;
mod tabs_geom_tests;
mod tabs_hit_tests;
mod text_char_tests;
mod text_em_tests;
mod title_tests;
mod toolbar_geom_tests;
mod ui_grid_tests;
mod ui_layout_tests;
mod ui_list_tests;
mod url_string_tests;
mod url_tests;
mod window_tests;
mod wrap_tests;
