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

/*
 * Installing a Qwen tier from the store. The listing the market publishes
 * reaches the personality as a shipped tier: its program, and its model as
 * a dependency of one tier of the signed catalogue, never a package to look
 * up. A model the volume holds under its pin is not fetched again, one whose
 * bytes are not the pin is never installed, and each way it can stop reads
 * in the store as its own reason, none of them "in no index".
 */

use std::fs;
use std::path::Path;

use crate::install::apps::{all as apps, wanted, Wanted};
use crate::install::family::{split, Family};
use crate::install::fetch_exit::{
    of_errno, ANYONE_NO_EXIT, ANYONE_UNREACHABLE, BUSY, DONE, LOCKED, MIRROR_UNREACHABLE, MISMATCH,
    NO_CATALOGUE, NO_MEMORY, NO_NETWORK, NO_ROOM, NO_VOLUME, NYM_NO_EXIT, NYM_UNREACHABLE, REFUSED,
    UNKEPT, USAGE, VOLUME_FAILED,
};
use crate::install::listing::package_arg;
use crate::install::model_dep::{fetched, needs_fetch, not_started, settle};
use crate::install::why::Why;
use crate::pins::pin_of;
use crate::store::progress::Progress;

/* The volume's answers, positive, as the installer gets them. */
const ENOENT: i64 = 2;
const EIO: i64 = 5;
const EAGAIN: i64 = 11;
const EACCES: i64 = 13;
const EBUSY: i64 = 16;
const EEXIST: i64 = 17;
const ENODEV: i64 = 19;
const ENOMEM: i64 = 12;
const ENOSPC: i64 = 28;
const EBADMSG: i64 = 74;

/* Every reason a model dependency can stop an install with. */
const MODEL_WHYS: [Why; 18] = [
    Why::NoVolume,
    Why::BootOffline,
    Why::NoMemory,
    Why::VolumeFailed,
    Why::VolumeLocked,
    Why::NoNetwork,
    Why::ModelUnknown,
    Why::ModelMismatch,
    Why::ModelFetch,
    Why::NoRoom,
    Why::ModelBusy,
    Why::ModelUnkept,
    Why::ModelTooLarge,
    Why::NymUnreachable,
    Why::AnyoneUnreachable,
    Why::MirrorUnreachable,
    Why::NymNoExit,
    Why::AnyoneNoExit,
];

/* The tail and program of each listing in the market's guest list. */
fn guests() -> Vec<(String, String)> {
    let at = Path::new(env!("CARGO_MANIFEST_DIR")).join("../capsule_market/linux-guests.json");
    let text = fs::read_to_string(at).expect("the market's guest list");
    let field = |entry: &str, key: &str| {
        let rest = entry.split(&format!("\"{key}\": \"")).nth(1).expect(key);
        rest.split('"').next().expect(key).to_string()
    };
    text.split("{\"tail\"")
        .skip(1)
        .map(|e| {
            let entry = format!("{{\"tail\"{e}");
            (field(&entry, "tail"), field(&entry, "program"))
        })
        .collect()
}

/* What the store says for an installer that stopped with `why`. */
fn said(why: Why) -> &'static [u8] {
    let code = u8::try_from(why.code()).expect("a reason fits the status byte");
    /* The kernel reports a stopped installer as 16 plus its exit code. */
    let status = 16 + i64::from(code);
    assert!(Progress::of(status) == Progress::Failed(code));
    Progress::Failed(code).sentence().expect("a stopped install is news").0
}

/* The store's sentence for a stop no reason names. */
fn unnamed() -> &'static [u8] {
    Progress::Failed(200).sentence().expect("a stopped install is news").0
}

#[test]
fn a_qwen_listing_is_its_program_and_a_model_tier_not_a_package() {
    let listed = guests();
    assert_eq!(listed.len(), apps().count(), "every shipped tier is listed, and only those");
    for (tail, program) in &listed {
        /* As the kernel hands it over: the listing's tail, then the family split. */
        let arg = package_arg(tail).expect("a usable package argument");
        let (family, name) = split(&arg);
        assert_eq!(family, Family::Alpine, "{tail}");
        let Wanted::Tier(app) = wanted(name) else {
            panic!("{tail} would be looked up in a package index");
        };
        /* The program the market pins is the one the tier starts. */
        let file = program.rsplit('/').next().expect("a program file");
        assert_eq!(app.program, format!("/bin/{file}").as_bytes(), "{tail}");
        /* Its model is a dependency of one tier of the signed catalogue. */
        assert_eq!(format!("qwen-{}", app.tier()), app.name);
        for m in app.models {
            let pin = pin_of(m).expect("every model file is pinned");
            assert_eq!(pin.tier, app.tier(), "{tail}");
        }
    }
    assert!(matches!(wanted("jq"), Wanted::Package));
    assert!(matches!(wanted("qwenchat"), Wanted::Package));
}

#[test]
fn a_tier_no_one_ships_is_refused_by_name() {
    assert!(matches!(wanted("qwen-giant"), Wanted::UnknownTier));
    assert!(matches!(wanted("qwen-"), Wanted::UnknownTier));
    /* A tier the signed catalogue does not list, or no catalogue at all. */
    assert_eq!(fetched(i64::from(USAGE)), Err(Why::ModelUnknown));
    assert_eq!(fetched(i64::from(NO_CATALOGUE)), Err(Why::ModelUnknown));
    /* A system built without the fetcher: MkToolRun answers ENOENT. */
    assert_eq!(not_started(-2), Why::ModelUnknown);
    assert_ne!(said(Why::ModelUnknown), said(Why::NotProvided));
    assert_ne!(said(Why::ModelUnknown), unnamed());
}

#[test]
fn a_model_held_to_its_pin_is_not_fetched_again() {
    assert_eq!(needs_fetch(&[Ok(491_400_032)]), Ok(false));
    assert_eq!(needs_fetch(&[Ok(3_993_201_344), Ok(689_872_288)]), Ok(false));
    /* One part of a split model missing: the tier goes to the fetcher. */
    assert_eq!(needs_fetch(&[Ok(3_993_201_344), Err(ENOENT)]), Ok(true));
}

#[test]
fn a_missing_model_is_fetched_and_never_in_no_index() {
    assert_eq!(needs_fetch(&[Err(ENOENT)]), Ok(true));
    for e in 0..=200 {
        assert_ne!(needs_fetch(&[Err(e)]), Err(Why::NotProvided), "errno {e}");
        assert_ne!(not_started(-e), Why::NotProvided, "errno {e}");
    }
    for status in -300..=300 {
        assert_ne!(fetched(status), Err(Why::NotProvided), "status {status}");
    }
}

#[test]
fn a_model_that_is_not_its_pin_is_never_installed() {
    /* The kernel discarded the bytes at the finish: the fetcher ends on it. */
    assert_eq!(of_errno(-EBADMSG), MISMATCH);
    assert_eq!(of_errno(-EEXIST), MISMATCH);
    assert_eq!(fetched(i64::from(MISMATCH)), Err(Why::ModelMismatch));
    /* A fetcher that says it is done is held to each file's record. */
    assert_eq!(settle(i64::from(DONE), &[Err(EBADMSG)]), Err(Why::ModelMismatch));
    assert_eq!(settle(i64::from(DONE), &[Ok(1), Err(EEXIST)]), Err(Why::ModelMismatch));
    assert_eq!(settle(i64::from(DONE), &[Ok(1), Err(ENOENT)]), Err(Why::ModelFetch));
    assert_eq!(settle(i64::from(DONE), &[Ok(1), Ok(2)]), Ok(()));
    /* Nothing but the fetcher's word that it is done, and every file whole, installs. */
    for status in -300..=300 {
        if status != i64::from(DONE) {
            assert!(settle(status, &[Ok(1)]).is_err(), "status {status}");
        }
    }
    assert_ne!(said(Why::ModelMismatch), unnamed());
}

#[test]
fn no_data_volume_and_no_network_are_told_apart() {
    /*
     * A live system with no data volume: the kernel answers ENODEV for a
     * disk with no plan. Said before any fetch, and never offered a retry.
     */
    assert_eq!(needs_fetch(&[Err(ENODEV)]), Err(Why::NoVolume));
    assert_eq!(of_errno(-ENODEV), NO_VOLUME);
    assert_eq!(fetched(i64::from(NO_VOLUME)), Err(Why::NoVolume));
    /*
     * A volume that is there and failed (EIO), or a disk not ready yet
     * (EAGAIN), is not a live boot: a retry may get past it.
     */
    for e in [EIO, EAGAIN] {
        assert_eq!(needs_fetch(&[Err(e)]), Err(Why::VolumeFailed), "errno {e}");
        assert_eq!(of_errno(-e), VOLUME_FAILED, "errno {e}");
    }
    assert_eq!(fetched(i64::from(VOLUME_FAILED)), Err(Why::VolumeFailed));
    assert_ne!(said(Why::VolumeFailed), said(Why::NoVolume));
    assert!(Progress::Failed(Why::VolumeFailed.code() as u8).retryable());
    assert!(!Progress::Failed(Why::NoVolume.code() as u8).retryable());
    assert_eq!(needs_fetch(&[Err(EACCES)]), Err(Why::VolumeLocked));
    assert_eq!(fetched(i64::from(LOCKED)), Err(Why::VolumeLocked));
    assert_eq!(needs_fetch(&[Err(ENOSPC)]), Err(Why::NoRoom));
    /* Too little memory for a live session's volume at all: its own reason, no retry. */
    assert_eq!(needs_fetch(&[Err(ENOMEM)]), Err(Why::NoMemory));
    assert_eq!(of_errno(-ENOMEM), NO_MEMORY);
    assert_eq!(fetched(i64::from(NO_MEMORY)), Err(Why::NoMemory));
    assert!(!Progress::Failed(Why::NoMemory.code() as u8).retryable());
    assert!(Progress::Failed(Why::NoRoom.code() as u8).retryable());
    assert_eq!(fetched(i64::from(NO_ROOM)), Err(Why::NoRoom));
    /*
     * No network: the boot runs none (ENETDOWN), which no retry on it
     * mends, or the chosen one is down, which a retry once it runs does.
     */
    assert_eq!(not_started(-100), Why::BootOffline);
    assert!(!Progress::Failed(Why::BootOffline.code() as u8).retryable());
    assert_eq!(fetched(i64::from(NO_NETWORK)), Err(Why::NoNetwork));
    assert!(Progress::Failed(Why::NoNetwork.code() as u8).retryable());
    assert_ne!(said(Why::BootOffline), said(Why::NoNetwork));
    assert_ne!(Why::NoVolume.code(), Why::NoNetwork.code());
    assert_ne!(said(Why::NoVolume), said(Why::NoNetwork));
    for why in [Why::NoVolume, Why::NoNetwork] {
        assert_ne!(said(why), said(Why::NotProvided));
        assert_ne!(said(why), unnamed());
    }
    /* A download that broke, or a mirror that never answered, is neither. */
    assert_eq!(fetched(i64::from(REFUSED)), Err(Why::ModelFetch));
    /* Nor is another download holding the fetcher or the volume's stream. */
    assert_eq!(not_started(-EBUSY), Why::ModelBusy);
    assert_eq!(of_errno(-EBUSY), BUSY);
    assert_eq!(fetched(i64::from(BUSY)), Err(Why::ModelBusy));
}

#[test]
fn every_model_reason_reads_as_its_own_sentence() {
    let package = [Why::Index, Why::NotProvided, Why::TooLarge, Why::Package, Why::NoMirror];
    let package: Vec<_> = package.into_iter().chain([Why::NoKeyring]).map(said).collect();
    for (i, why) in MODEL_WHYS.iter().enumerate() {
        let line = said(*why);
        assert_ne!(line, unnamed(), "{why:?}");
        assert!(!package.contains(&line), "{why:?} reads as a package's failure");
        for other in &MODEL_WHYS[i + 1..] {
            assert_ne!(line, said(*other), "{why:?} and {other:?}");
        }
        let text = String::from_utf8_lossy(line).to_lowercase();
        assert!(!text.contains("index") && !text.contains("package"), "{why:?}");
    }
}

/*
 * A tier whose file names the volume cannot keep (the Coder 7B, 14B and 32B
 * tiers today) is not a download that broke: the store must not ask for a
 * retry that cannot succeed.
 */
#[test]
fn a_model_the_volume_cannot_keep_is_not_offered_a_retry() {
    assert_eq!(fetched(i64::from(UNKEPT)), Err(Why::ModelUnkept));
    let line = String::from_utf8_lossy(said(Why::ModelUnkept)).to_lowercase();
    assert!(!line.contains("retry"), "{line}");
    assert_ne!(said(Why::ModelUnkept), said(Why::ModelFetch));
}

/*
 * A live boot has no data volume, so a model cannot be kept. That is not a
 * fault to retry: the store says it is a live boot, names the Install app,
 * shows no red, and its button offers no retry.
 */
#[test]
fn a_live_boot_points_to_the_installer_and_offers_no_retry() {
    let stopped = Progress::Failed(Why::NoVolume.code() as u8);
    assert!(stopped.needs_installed_system());
    let (line, tone) = stopped.sentence().expect("a stopped install is news");
    let text = String::from_utf8_lossy(line);
    assert!(text.contains("live boot"), "{text}");
    assert!(text.contains("Install is in the dock"), "{text}");
    assert!(!text.to_lowercase().contains("retry"), "{text}");
    assert_ne!(tone, crate::store::tone::DANGER);
    assert_eq!(stopped.button(true), b"Live boot");
    /* Every other stop still offers a retry. */
    assert_eq!(Progress::Failed(Why::ModelFetch.code() as u8).button(true), b"Retry");
    assert!(!Progress::Failed(Why::NoNetwork.code() as u8).needs_installed_system());
}

/*
 * A network that runs but reached no mirror before a byte came is said as
 * not reachable, by name, with what to do; a download that started and
 * stopped still says it goes on from there. Both offer a retry.
 */
#[test]
fn an_unreachable_network_is_named_and_not_a_cut_download() {
    let cases = [
        (NYM_UNREACHABLE, Why::NymUnreachable, "Nym is not reachable from this machine"),
        (ANYONE_UNREACHABLE, Why::AnyoneUnreachable, "Anyone is not reachable from this machine"),
        (MIRROR_UNREACHABLE, Why::MirrorUnreachable, "The model mirror is not reachable"),
    ];
    let cut = String::from_utf8_lossy(said(Why::ModelFetch)).into_owned();
    assert!(cut.contains("did not finish downloading") && cut.contains("go on from there"), "{cut}");
    for (status, why, start) in cases {
        assert_eq!(fetched(i64::from(status)), Err(why));
        let line = String::from_utf8_lossy(said(why)).into_owned();
        assert!(line.starts_with(start), "{line}");
        assert!(line.contains("Check the network, or choose another in Settings"), "{line}");
        assert!(!line.contains("did not finish"), "{line}");
        assert!(Progress::Failed(why.code() as u8).retryable());
    }
    let statuses = [REFUSED, NO_NETWORK, NYM_UNREACHABLE, ANYONE_UNREACHABLE, MIRROR_UNREACHABLE];
    for (i, a) in statuses.iter().enumerate() {
        assert!(statuses[i + 1..].iter().all(|b| a != b));
    }
}

/* Exits that did not answer are their own reason, offer direct, and are not a cut download. */
#[test]
fn no_exit_answering_is_its_own_reason_and_offers_direct() {
    for (status, why, start) in [
        (NYM_NO_EXIT, Why::NymNoExit, "No Nym exit answered; try again, or press d to download direct"),
        (ANYONE_NO_EXIT, Why::AnyoneNoExit, "No Anyone circuit reached the mirror; try again"),
    ] {
        assert_eq!(fetched(i64::from(status)), Err(why));
        let line = String::from_utf8_lossy(said(why)).into_owned();
        assert!(line.starts_with(start), "{line}");
        assert!(line.contains("the mirror sees this machine's address"), "{line}");
        assert!(Progress::Failed(why.code() as u8).retryable());
        assert_ne!(said(why), said(Why::NymUnreachable));
        assert_ne!(said(why), said(Why::ModelFetch));
    }
    assert!(crate::store::route_offer::ROUTE_REASONS.contains(&(Why::NymNoExit.code() as u8)));
    assert!(crate::store::route_offer::ROUTE_REASONS.contains(&(Why::NymUnreachable.code() as u8)));
}
