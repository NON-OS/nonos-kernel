// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/memory.rs - AgentMemory, MemoryEntry

use crate::agents::memory::{AgentMemory, MemoryEntry, MAX_ENTRIES};
use crate::test::framework::TestResult;

pub(crate) fn test_memory_new() -> TestResult {
    let mem = AgentMemory::new(1);
    if mem.agent_id != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_store_and_recall() -> TestResult {
    let mem = AgentMemory::new(100);

    mem.store(b"test_key", b"test_value", 5);

    let recalled = mem.recall(b"test_key");
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().as_slice() != b"test_value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_recall_nonexistent() -> TestResult {
    let mem = AgentMemory::new(100);

    let recalled = mem.recall(b"nonexistent");
    if recalled.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_store_update_existing() -> TestResult {
    let mem = AgentMemory::new(100);

    mem.store(b"key", b"value1", 5);
    mem.store(b"key", b"value2", 5);

    let recalled = mem.recall(b"key");
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().as_slice() != b"value2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_multiple_keys() -> TestResult {
    let mem = AgentMemory::new(100);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);
    mem.store(b"key3", b"value3", 5);

    if mem.recall(b"key1").unwrap().as_slice() != b"value1" {
        return TestResult::Fail;
    }
    if mem.recall(b"key2").unwrap().as_slice() != b"value2" {
        return TestResult::Fail;
    }
    if mem.recall(b"key3").unwrap().as_slice() != b"value3" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_isolation_between_agents() -> TestResult {
    let mem1 = AgentMemory::new(200);
    let mem2 = AgentMemory::new(201);

    mem1.store(b"shared_key", b"agent1_value", 5);
    mem2.store(b"shared_key", b"agent2_value", 5);

    if mem1.recall(b"shared_key").unwrap().as_slice() != b"agent1_value" {
        return TestResult::Fail;
    }
    if mem2.recall(b"shared_key").unwrap().as_slice() != b"agent2_value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_search_basic() -> TestResult {
    let mem = AgentMemory::new(300);

    mem.store(b"key1", b"hello world", 5);
    mem.store(b"key2", b"goodbye world", 5);
    mem.store(b"key3", b"hello there", 5);

    let results = mem.search(b"hello");
    if results.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_search_no_results() -> TestResult {
    let mem = AgentMemory::new(300);

    mem.store(b"key1", b"hello", 5);
    mem.store(b"key2", b"world", 5);

    let results = mem.search(b"xyz");
    if !results.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_search_empty_query() -> TestResult {
    let mem = AgentMemory::new(300);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);

    let results = mem.search(b"");
    if results.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_search_isolation() -> TestResult {
    let mem1 = AgentMemory::new(400);
    let mem2 = AgentMemory::new(401);

    mem1.store(b"key", b"findme", 5);
    mem2.store(b"key", b"findme", 5);

    let results1 = mem1.search(b"findme");
    let results2 = mem2.search(b"findme");

    if results1.len() != 1 {
        return TestResult::Fail;
    }
    if results2.len() != 1 {
        return TestResult::Fail;
    }
    if results1[0].agent_id != 400 {
        return TestResult::Fail;
    }
    if results2[0].agent_id != 401 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_recent() -> TestResult {
    let mem = AgentMemory::new(500);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);
    mem.store(b"key3", b"value3", 5);

    let recent = mem.recent(2);
    if recent.len() != 2 {
        return TestResult::Fail;
    }
    if recent[0].value.as_slice() != b"value3" {
        return TestResult::Fail;
    }
    if recent[1].value.as_slice() != b"value2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_recent_more_than_available() -> TestResult {
    let mem = AgentMemory::new(500);

    mem.store(b"key1", b"value1", 5);

    let recent = mem.recent(10);
    if recent.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_recent_zero() -> TestResult {
    let mem = AgentMemory::new(500);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);

    let recent = mem.recent(0);
    if !recent.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_recent_isolation() -> TestResult {
    let mem1 = AgentMemory::new(600);
    let mem2 = AgentMemory::new(601);

    mem1.store(b"key1", b"value1", 5);
    mem2.store(b"key2", b"value2", 5);

    let recent1 = mem1.recent(10);
    let recent2 = mem2.recent(10);

    if recent1.len() != 1 {
        return TestResult::Fail;
    }
    if recent2.len() != 1 {
        return TestResult::Fail;
    }
    if recent1[0].agent_id != 600 {
        return TestResult::Fail;
    }
    if recent2[0].agent_id != 601 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_importance_stored() -> TestResult {
    let mem = AgentMemory::new(700);

    mem.store(b"low", b"value", 1);
    mem.store(b"high", b"value", 10);

    let recent = mem.recent(2);
    let low_entry = recent.iter().find(|e| e.key[..3] == *b"low").unwrap();
    let high_entry = recent.iter().find(|e| e.key[..4] == *b"high").unwrap();

    if low_entry.importance != 1 {
        return TestResult::Fail;
    }
    if high_entry.importance != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_key_truncation() -> TestResult {
    let mem = AgentMemory::new(800);

    let long_key = [b'x'; 100];
    mem.store(&long_key, b"value", 5);

    let truncated_key = [b'x'; 64];
    let recalled = mem.recall(&truncated_key);
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().as_slice() != b"value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_entry_timestamp() -> TestResult {
    let mem = AgentMemory::new(900);

    mem.store(b"key", b"value", 5);

    let recent = mem.recent(1);
    if recent.len() != 1 {
        return TestResult::Fail;
    }
    if recent[0].timestamp == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_entry_clone() -> TestResult {
    let entry = MemoryEntry {
        key: [b'k'; 64],
        value: b"test_value".to_vec(),
        agent_id: 1,
        timestamp: 12345,
        importance: 7,
    };

    let cloned = entry.clone();
    if cloned.key != entry.key {
        return TestResult::Fail;
    }
    if cloned.value != entry.value {
        return TestResult::Fail;
    }
    if cloned.agent_id != entry.agent_id {
        return TestResult::Fail;
    }
    if cloned.timestamp != entry.timestamp {
        return TestResult::Fail;
    }
    if cloned.importance != entry.importance {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_empty_value() -> TestResult {
    let mem = AgentMemory::new(1000);

    mem.store(b"key", b"", 5);

    let recalled = mem.recall(b"key");
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if !recalled.unwrap().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_large_value() -> TestResult {
    let mem = AgentMemory::new(1001);

    let large_value = [b'x'; 10000];
    mem.store(b"key", &large_value, 5);

    let recalled = mem.recall(b"key");
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().len() != 10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_max_entries_constant() -> TestResult {
    if MAX_ENTRIES != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_binary_key() -> TestResult {
    let mem = AgentMemory::new(1100);

    let binary_key = b"\x00\x01\x02\x03";
    mem.store(binary_key, b"value", 5);

    let recalled = mem.recall(binary_key);
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().as_slice() != b"value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_binary_value() -> TestResult {
    let mem = AgentMemory::new(1100);

    let binary_value = b"\x00\x01\x02\x03\xff\xfe";
    mem.store(b"key", binary_value, 5);

    let recalled = mem.recall(b"key");
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().as_slice() != binary_value {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_search_partial_match() -> TestResult {
    let mem = AgentMemory::new(1200);

    mem.store(b"key1", b"abcdefgh", 5);
    mem.store(b"key2", b"cdefghij", 5);
    mem.store(b"key3", b"efghijkl", 5);

    let results = mem.search(b"cdef");
    if results.len() != 2 {
        return TestResult::Fail;
    }

    let results = mem.search(b"efgh");
    if results.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
