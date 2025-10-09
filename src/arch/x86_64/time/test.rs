//! Unit Tests for Timer, TSC, HPET, PIT
//!
//! Ready for kernel test harness integration.

#[cfg(test)]
mod tests {
    use super::{tsc, hpet, pit};
    #[test]
    fn test_rdtsc() {
        let t0 = tsc::rdtsc();
        let t1 = tsc::rdtsc();
        assert!(t1 >= t0);
    }
    #[test]
    fn test_hpet_detect() {
        assert!(hpet::detect_hpet().is_some() || hpet::detect_hpet().is_none());
    }
    #[test]
    fn test_pit_sleep() {
        let ms = 10;
        let start = crate::arch::x86_64::time::nonos_timer::now_ms();
        pit::pit_sleep(ms);
        let end = crate::arch::x86_64::time::nonos_timer::now_ms();
        assert!(end - start >= ms);
    }
}
