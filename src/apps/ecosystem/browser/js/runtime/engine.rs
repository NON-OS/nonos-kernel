extern crate alloc;
use super::globals;
use super::globals_ext;
use super::natives;
use super::scope::Scope;
use super::value::JsValue;
use crate::apps::ecosystem::browser::js::event_loop::{MicrotaskQueue, TimerStore};
use crate::apps::ecosystem::browser::js::parser::Parser;
use crate::apps::ecosystem::browser::js::prototype::BuiltinPrototypes;
use alloc::string::String;

pub struct JsRuntime {
    pub scope: Scope,
    pub this: JsValue,
    pub return_val: Option<JsValue>,
    pub break_flag: bool,
    pub continue_flag: bool,
    pub prototypes: BuiltinPrototypes,
    pub microtasks: MicrotaskQueue,
    pub timers: TimerStore,
    pub thrown: Option<JsValue>,
    pub current_time: u64,
}

impl JsRuntime {
    pub fn new() -> Self {
        let mut rt = Self {
            scope: Scope::new(),
            this: JsValue::Undefined,
            return_val: None,
            break_flag: false,
            continue_flag: false,
            prototypes: BuiltinPrototypes::new(),
            microtasks: MicrotaskQueue::new(),
            timers: TimerStore::new(),
            thrown: None,
            current_time: 0,
        };
        rt.init_globals();
        rt
    }

    fn init_globals(&mut self) {
        self.scope.declare(String::from("undefined"), JsValue::Undefined);
        self.scope.declare(String::from("NaN"), JsValue::Number(f64::NAN));
        self.scope.declare(String::from("Infinity"), JsValue::Number(f64::INFINITY));
        self.scope.declare(String::from("console"), globals::create_console());
        self.scope.declare(String::from("Math"), globals::create_math());
        self.scope.declare(String::from("JSON"), globals::create_json());
        self.scope.declare(String::from("parseInt"), JsValue::NativeFunc(natives::parse_int));
        self.scope.declare(String::from("parseFloat"), JsValue::NativeFunc(natives::parse_float));
        self.scope.declare(String::from("isNaN"), JsValue::NativeFunc(natives::is_nan));
        self.scope.declare(String::from("isFinite"), JsValue::NativeFunc(natives::is_finite));
        globals_ext::register_all(&mut self.scope);
    }

    pub fn execute(&mut self, src: &str) -> JsValue {
        let program = Parser::new(src).parse();
        let mut result = JsValue::Undefined;
        for stmt in program.body {
            result = self.eval_stmt(&stmt);
            if self.return_val.is_some() || self.thrown.is_some() {
                break;
            }
        }
        self.return_val.take().unwrap_or(result)
    }
}
