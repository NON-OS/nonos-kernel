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

use super::manager::NoxProcessManager;
use super::types::*;
use alloc::{string::String, vec};

#[test]
fn create_and_get() {
    let mgr = NoxProcessManager::new();
    let pid = mgr.create("/bin/app", &["-v", "--opt"], None, Some(1)).unwrap();
    let snap = mgr.get(pid).unwrap();
    assert_eq!(snap.pid, pid);
    assert_eq!(snap.node, 1);
    assert_eq!(snap.state, NoxState::Ready);
    assert_eq!(snap.executable_path, "/bin/app");
    assert_eq!(snap.args, vec![String::from("-v"), String::from("--opt")]);
}

#[test]
fn invalid_inputs() {
    let mgr = NoxProcessManager::new();
    assert_eq!(mgr.create("", &[], None, None).unwrap_err(), "EINVAL");

    let huge = "A".repeat(ARGS_MAX_TOTAL_BYTES + 1);
    assert_eq!(
        mgr.create("/bin/x", &[&huge], None, None).unwrap_err(),
        "E2BIG"
    );

    let long_path = "p".repeat(PATH_MAX_BYTES + 1);
    assert_eq!(
        mgr.create(&long_path, &[], None, None).unwrap_err(),
        "EINVAL"
    );
}

#[test]
fn state_transitions() {
    let mgr = NoxProcessManager::new();
    let pid = mgr.create("/bin/a", &[], None, None).unwrap();

    mgr.set_state(pid, NoxState::Running).unwrap();
    assert_eq!(mgr.get(pid).unwrap().state, NoxState::Running);
    mgr.set_state(pid, NoxState::Suspended).unwrap();
    assert_eq!(mgr.get(pid).unwrap().state, NoxState::Suspended);
    mgr.set_state(pid, NoxState::Ready).unwrap();
    assert_eq!(mgr.get(pid).unwrap().state, NoxState::Ready);

    mgr.terminate(pid, 0).unwrap();
    assert!(mgr.set_state(pid, NoxState::Ready).is_err());
}

#[test]
fn migration_flow() {
    let mgr = NoxProcessManager::new();
    let pid = mgr.create("/bin/m", &[], None, Some(0)).unwrap();
    mgr.request_migration(pid, 2).unwrap();
    {
        let p = mgr.get(pid).unwrap();
        assert!(matches!(p.state, NoxState::Migrating { from_node: 0, to_node: 2 }));
        assert_eq!(p.pending_migration_to, Some(2));
    }
    mgr.complete_migration(pid).unwrap();
    let p2 = mgr.get(pid).unwrap();
    assert_eq!(p2.node, 2);
    assert_eq!(p2.state, NoxState::Ready);
    assert_eq!(p2.pending_migration_to, None);
}

#[test]
fn cancel_migration() {
    let mgr = NoxProcessManager::new();
    let pid = mgr.create("/bin/m2", &[], None, Some(1)).unwrap();
    mgr.request_migration(pid, 3).unwrap();
    mgr.cancel_migration(pid).unwrap();
    let p = mgr.get(pid).unwrap();
    assert_eq!(p.node, 1);
    assert_eq!(p.state, NoxState::Ready);
    assert_eq!(p.pending_migration_to, None);
}

#[test]
fn remove_only_after_terminated() {
    let mgr = NoxProcessManager::new();
    let pid = mgr.create("/bin/rm", &[], None, None).unwrap();
    assert_eq!(mgr.remove(pid).unwrap_err(), "EBUSY");
    mgr.terminate(pid, 9).unwrap();
    assert!(mgr.remove(pid).unwrap());
    assert!(mgr.get(pid).is_none());
}

#[test]
fn list_and_filter_by_node() {
    let mgr = NoxProcessManager::new();
    let a = mgr.create("/bin/a", &[], None, Some(0)).unwrap();
    let b = mgr.create("/bin/b", &[], None, Some(1)).unwrap();
    let c = mgr.create("/bin/c", &[], None, Some(1)).unwrap();
    let all = mgr.list();
    assert!(all.contains(&a) && all.contains(&b) && all.contains(&c));
    let n1 = mgr.list_by_node(1);
    assert!(n1.contains(&b) && n1.contains(&c) && !n1.contains(&a));
}
