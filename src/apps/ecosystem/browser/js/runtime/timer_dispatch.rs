extern crate alloc;
use super::engine::JsRuntime;
use super::value::JsValue;

impl JsRuntime {
    pub(super) fn dispatch_builtin(&mut self, name: &str, args: &[JsValue]) -> Option<JsValue> {
        match name {
            "setTimeout" => Some(self.builtin_set_timeout(args)),
            "setInterval" => Some(self.builtin_set_interval(args)),
            "clearTimeout" | "clearInterval" => Some(self.builtin_clear_timer(args)),
            "queueMicrotask" => Some(self.builtin_queue_microtask(args)),
            _ => None,
        }
    }

    fn builtin_set_timeout(&mut self, args: &[JsValue]) -> JsValue {
        let callback = args.first().cloned().unwrap_or(JsValue::Undefined);
        let delay = args.get(1).map(|v| v.to_number() as u64).unwrap_or(0);
        let id = self.timers.set_timeout(callback, delay, self.current_time);
        JsValue::Number(id as f64)
    }

    fn builtin_set_interval(&mut self, args: &[JsValue]) -> JsValue {
        let callback = args.first().cloned().unwrap_or(JsValue::Undefined);
        let delay = args.get(1).map(|v| v.to_number() as u64).unwrap_or(0);
        let id = self.timers.set_interval(callback, delay, self.current_time);
        JsValue::Number(id as f64)
    }

    fn builtin_clear_timer(&mut self, args: &[JsValue]) -> JsValue {
        let id = args.first().map(|v| v.to_number() as u32).unwrap_or(0);
        self.timers.clear(id);
        JsValue::Undefined
    }

    fn builtin_queue_microtask(&mut self, args: &[JsValue]) -> JsValue {
        let callback = args.first().cloned().unwrap_or(JsValue::Undefined);
        self.microtasks.enqueue(callback);
        JsValue::Undefined
    }
}
