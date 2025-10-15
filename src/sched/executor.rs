//! NØNOS Kernel Task Executor 
use alloc::collections::VecDeque;
use core::future::Future;
use core::pin::Pin;
use spin::Mutex;

/// Represents an asynchronous kernel task.
pub struct AsyncTask {
    pub name: &'static str,
    pub future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    pub complete: bool,
}

impl AsyncTask {
    /// Polls the async task.
    pub fn poll(&mut self) -> bool {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        // Minimal waker for polling futures in kernel space.
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker { dummy_raw_waker() }
        fn dummy_raw_waker() -> RawWaker {
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        match self.future.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {
                self.complete = true;
                true
            }
            Poll::Pending => false,
        }
    }
}

static ASYNC_QUEUE: Mutex<VecDeque<AsyncTask>> = Mutex::new(VecDeque::new());

/// Spawn a new async kernel task.
pub fn spawn_async(name: &'static str, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
    ASYNC_QUEUE.lock().push_back(AsyncTask {
        name,
        future,
        complete: false,
    });
}

/// Poll all async tasks in the queue, removing completed ones.
pub fn poll_async_tasks() {
    let mut queue = ASYNC_QUEUE.lock();
    queue.retain_mut(|task| !task.poll());
}

/// Returns the number of pending async tasks.
pub fn pending_async_tasks() -> usize {
    ASYNC_QUEUE.lock().iter().filter(|task| !task.complete).count()
}
