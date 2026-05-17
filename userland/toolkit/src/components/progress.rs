pub fn progress_pct(done: u32, total: u32) -> u8 {
    if total == 0 {
        return 0;
    }
    ((done.min(total) as u64 * 100) / total as u64) as u8
}
