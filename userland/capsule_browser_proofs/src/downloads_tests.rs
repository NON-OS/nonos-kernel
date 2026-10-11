// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The session's download records and the start page's lines about them.

use crate::browser::shell::dl_line::{count_line, status_line};
use crate::browser::shell::downloads::{
    counts, push, push_failed, push_saved, received, MAX_DOWNLOADS, MAX_SAVE,
};
use crate::browser::shell::types::{DlState, Download};

fn list(states: &[DlState]) -> Vec<Download> {
    let mut l = Vec::new();
    for (i, s) in states.iter().enumerate() {
        push(&mut l, &format!("https://h.com/f{i}.zip"), 1, i as i64, s.clone());
    }
    l
}

fn failed() -> DlState {
    DlState::Failed("x".into())
}

#[test]
fn push_names_the_file_and_drops_the_oldest_past_the_cap() {
    let l = list(&[DlState::Saving]);
    assert_eq!(l[0].name, "f0.zip");
    let l = list(&vec![DlState::Saving; MAX_DOWNLOADS + 5]);
    assert_eq!(l.len(), MAX_DOWNLOADS);
    assert_eq!(l[0].at_ms, 5);
}

#[test]
fn counts_are_all_saved_failed() {
    let l = list(&[DlState::Saving, DlState::Saved, failed(), DlState::Saved, failed()]);
    assert_eq!(counts(&l), [5, 2, 2]);
    assert_eq!(counts(&[]), [0, 0, 0]);
}

#[test]
fn push_saved_settles_only_the_matching_record() {
    let mut l = list(&[DlState::Saving, DlState::Saving]);
    push_saved(&mut l, "https://h.com/f1.zip", 1, Ok("f1 (2).zip".into()));
    assert_eq!((l[1].state.clone(), l[1].name.as_str()), (DlState::Saved, "f1 (2).zip"));
    push_saved(&mut l, "https://h.com/f0.zip", 0, Err("disk full"));
    assert_eq!(l[0].state, DlState::Failed("disk full".into()));
    let mut l = list(&[DlState::Saving]);
    push_saved(&mut l, "https://h.com/f0.zip", 99, Ok("y".into()));
    push_saved(&mut l, "https://other/", 0, Ok("y".into()));
    assert_eq!((l[0].state.clone(), l[0].name.as_str()), (DlState::Saving, "f0.zip"));
}

#[test]
fn received_keeps_a_body_up_to_the_save_cap() {
    let d = received("u".into(), vec![1, 2, 3]);
    assert_eq!((d.bytes, d.body.as_deref()), (3, Some(&[1u8, 2, 3][..])));
    assert!(received("u".into(), vec![0; MAX_SAVE]).body.is_some());
    let d = received("u".into(), vec![0; MAX_SAVE + 1]);
    assert_eq!((d.bytes, d.body.is_none()), (MAX_SAVE as u64 + 1, true));
}

#[test]
fn the_start_page_lines_say_how_downloads_stand() {
    assert_eq!(count_line(&[]), "Downloads: none yet");
    assert_eq!(count_line(&list(&[DlState::Saved, DlState::Saving])), "Downloads: 1 saved");
    assert_eq!(count_line(&list(&[DlState::Saved, failed()])), "Downloads: 1 saved, 1 failed");
    let mut l = Vec::new();
    push(&mut l, "https://h.com/a.iso", 3 * 1024 * 1024 / 2, 0, DlState::Saving);
    assert_eq!(status_line(&l[0]), "Saving a.iso");
    l[0].state = DlState::Saved;
    assert_eq!(status_line(&l[0]), "Saved a.iso (1.5 MB)");
    push_failed(&mut l, "https://h.com/b.iso", 0, 1, "too large");
    assert_eq!(status_line(&l[1]), "b.iso not saved: too large");
}
