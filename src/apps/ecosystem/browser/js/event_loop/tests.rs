#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::js::event_loop::*;
    use crate::apps::ecosystem::browser::js::runtime::JsValue;

    #[test]
    fn test_microtask_enqueue_drain() {
        let mut q = MicrotaskQueue::new();
        q.enqueue(JsValue::Number(1.0));
        q.enqueue(JsValue::Number(2.0));
        let drained = q.drain();
        assert_eq!(drained.len(), 2);
        assert!(q.is_empty());
    }

    #[test]
    fn test_set_timeout_fires() {
        let mut timers = TimerStore::new();
        let id = timers.set_timeout(JsValue::Bool(true), 100, 0);
        let fired = timers.fire_expired(100);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_set_timeout_not_yet() {
        let mut timers = TimerStore::new();
        timers.set_timeout(JsValue::Bool(true), 100, 0);
        let fired = timers.fire_expired(50);
        assert!(fired.is_empty());
    }

    #[test]
    fn test_clear_timeout() {
        let mut timers = TimerStore::new();
        let id = timers.set_timeout(JsValue::Bool(true), 100, 0);
        timers.clear(id);
        let fired = timers.fire_expired(200);
        assert!(fired.is_empty());
    }

    #[test]
    fn test_set_interval_repeats() {
        let mut timers = TimerStore::new();
        timers.set_interval(JsValue::Bool(true), 100, 0);
        let first = timers.fire_expired(100);
        assert_eq!(first.len(), 1);
        let second = timers.fire_expired(200);
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn test_event_loop_tick_drains_microtasks_first() {
        let mut microtasks = MicrotaskQueue::new();
        let mut timers = TimerStore::new();
        microtasks.enqueue(JsValue::Number(1.0));
        timers.set_timeout(JsValue::Number(2.0), 0, 0);
        let result = event_loop_tick(&mut microtasks, &mut timers, 0);
        assert_eq!(result.microtasks_fired.len(), 1);
        assert!(result.timer_fired.is_some());
    }
}
