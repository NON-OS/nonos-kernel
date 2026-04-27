use crate::process::core::thread_group::ThreadGroup;
use crate::test::framework::TestResult;

pub fn thread_group_new() -> TestResult {
    let tg = ThreadGroup::new(100);
    if tg.tgid != 100 {
        return TestResult::Fail;
    }
    if tg.thread_count() != 1 {
        return TestResult::Fail;
    }
    if !tg.is_leader(100) {
        return TestResult::Fail;
    }
    if tg.shared_memory.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_add_thread() -> TestResult {
    let tg = ThreadGroup::new(100);
    if tg.thread_count() != 1 {
        return TestResult::Fail;
    }
    tg.add_thread(101);
    if tg.thread_count() != 2 {
        return TestResult::Fail;
    }
    tg.add_thread(102);
    if tg.thread_count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_remove_thread() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    if tg.thread_count() != 3 {
        return TestResult::Fail;
    }
    tg.remove_thread(101);
    if tg.thread_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_remove_nonexistent() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    if tg.thread_count() != 2 {
        return TestResult::Fail;
    }
    tg.remove_thread(999);
    if tg.thread_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_is_leader() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    if !tg.is_leader(100) {
        return TestResult::Fail;
    }
    if tg.is_leader(101) {
        return TestResult::Fail;
    }
    if tg.is_leader(102) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_thread_count_atomic() -> TestResult {
    let tg = ThreadGroup::new(1);
    if tg.thread_count() != 1 {
        return TestResult::Fail;
    }
    for i in 2..=10 {
        tg.add_thread(i);
    }
    if tg.thread_count() != 10 {
        return TestResult::Fail;
    }
    for i in 2..=5 {
        tg.remove_thread(i);
    }
    if tg.thread_count() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_remove_leader() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    if tg.thread_count() != 2 {
        return TestResult::Fail;
    }
    tg.remove_thread(100);
    if tg.thread_count() != 1 {
        return TestResult::Fail;
    }
    if !tg.is_leader(100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_tgid_unchanged() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.remove_thread(100);
    if tg.tgid != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_threads_list() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    let threads = tg.threads.read();
    if !threads.contains(&100) {
        return TestResult::Fail;
    }
    if !threads.contains(&101) {
        return TestResult::Fail;
    }
    if !threads.contains(&102) {
        return TestResult::Fail;
    }
    if threads.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_remove_all_except_leader() -> TestResult {
    let tg = ThreadGroup::new(100);
    tg.add_thread(101);
    tg.add_thread(102);
    tg.add_thread(103);
    tg.remove_thread(101);
    tg.remove_thread(102);
    tg.remove_thread(103);
    if tg.thread_count() != 1 {
        return TestResult::Fail;
    }
    let threads = tg.threads.read();
    if !threads.contains(&100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn thread_group_multiple_add_remove() -> TestResult {
    let tg = ThreadGroup::new(1);
    for i in 2..=100 {
        tg.add_thread(i);
    }
    if tg.thread_count() != 100 {
        return TestResult::Fail;
    }
    for i in 2..=50 {
        tg.remove_thread(i);
    }
    if tg.thread_count() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
