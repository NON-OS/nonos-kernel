use crate::process::core::thread_group::ThreadGroup;

#[test]
fn thread_group_new() {
    let tg = ThreadGroup::new(100);
    assert_eq!(tg.tgid, 100);
    assert_eq!(tg.thread_count(), 1);
    assert!(tg.is_leader(100));
    assert!(tg.shared_memory.is_none());
}

#[test]
fn thread_group_add_thread() {
    let tg = ThreadGroup::new(100);
    assert_eq!(tg.thread_count(), 1);
    tg.add_thread(101);
    assert_eq!(tg.thread_count(), 2);
    tg.add_thread(102);
    assert_eq!(tg.thread_count(), 3);
}

#[test]
fn thread_group_remove_thread() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    assert_eq!(tg.thread_count(), 3);
    tg.remove_thread(101);
    assert_eq!(tg.thread_count(), 2);
}

#[test]
fn thread_group_remove_nonexistent() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    assert_eq!(tg.thread_count(), 2);
    tg.remove_thread(999);
    assert_eq!(tg.thread_count(), 2);
}

#[test]
fn thread_group_is_leader() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    assert!(tg.is_leader(100));
    assert!(!tg.is_leader(101));
    assert!(!tg.is_leader(102));
}

#[test]
fn thread_group_thread_count_atomic() {
    let tg = ThreadGroup::new(1);
    assert_eq!(tg.thread_count(), 1);
    for i in 2..=10 {
        tg.add_thread(i);
    }
    assert_eq!(tg.thread_count(), 10);
    for i in 2..=5 {
        tg.remove_thread(i);
    }
    assert_eq!(tg.thread_count(), 6);
}

#[test]
fn thread_group_remove_leader() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    assert_eq!(tg.thread_count(), 2);
    tg.remove_thread(100);
    assert_eq!(tg.thread_count(), 1);
    assert!(tg.is_leader(100));
}

#[test]
fn thread_group_tgid_unchanged() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.remove_thread(100);
    assert_eq!(tg.tgid, 100);
}

#[test]
fn thread_group_threads_list() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    let threads = tg.threads.read();
    assert!(threads.contains(&100));
    assert!(threads.contains(&101));
    assert!(threads.contains(&102));
    assert_eq!(threads.len(), 3);
}

#[test]
fn thread_group_remove_all_except_leader() {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    tg.add_thread(103);
    tg.remove_thread(101);
    tg.remove_thread(102);
    tg.remove_thread(103);
    assert_eq!(tg.thread_count(), 1);
    let threads = tg.threads.read();
    assert!(threads.contains(&100));
}

#[test]
fn thread_group_multiple_add_remove() {
    let tg = ThreadGroup::new(1);
    for i in 2..=100 {
        tg.add_thread(i);
    }
    assert_eq!(tg.thread_count(), 100);
    for i in 2..=50 {
        tg.remove_thread(i);
    }
    assert_eq!(tg.thread_count(), 50);
}
