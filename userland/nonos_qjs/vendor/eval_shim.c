/* NONOS Operating System
 * Copyright (C) 2026 NONOS Contributors
 * SPDX-License-Identifier: AGPL-3.0
 *
 * A thin C surface over QuickJS whose inline JSValue handling cannot be called
 * from Rust directly. Everything that touches a JSValue stays here; Rust only
 * exchanges runtime/context handles and malloc'd C strings.
 */
#include "quickjs.h"
#include <stddef.h>

void *malloc(size_t);
void *calloc(size_t, size_t);
void free(void *);
void *realloc(void *, size_t);
size_t malloc_usable_size(const void *);
size_t strlen(const char *);

/* Hand QuickJS our allocator explicitly. Its default picks a usable-size
 * function by platform macro, and on this bare target that resolves to a stub
 * returning 0, which breaks the arena allocator's block accounting and corrupts
 * the runtime during JS_NewRuntime. Routing usable-size to our real header read
 * keeps the arena correct. */
static void *mf_calloc(void *o, size_t n, size_t s) { (void)o; return calloc(n, s); }
static void *mf_malloc(void *o, size_t s) { (void)o; return malloc(s); }
static void mf_free(void *o, void *p) { (void)o; free(p); }
static void *mf_realloc(void *o, void *p, size_t s) { (void)o; return realloc(p, s); }
static size_t mf_usable(const void *p) { return malloc_usable_size(p); }

static const JSMallocFunctions nonos_mf = {
    mf_calloc, mf_malloc, mf_free, mf_realloc, mf_usable,
};

static char *dup_cstr(const char *s) {
    if (!s) return 0;
    size_t n = strlen(s) + 1;
    char *r = (char *)malloc(n);
    if (r) for (size_t i = 0; i < n; i++) r[i] = s[i];
    return r;
}

JSRuntime *njs_new_runtime(void) { return JS_NewRuntime2(&nonos_mf, NULL); }

/* Limits on what a page's code may take.
 *
 * A page could run `while(true){}` and the browser, which runs scripts on
 * the thread that draws and reads input, never came back: the window froze
 * until the capsule was killed. Each entry into the engine from the browser
 * (a page script, a timer flush, a UI event, the load events) now gets a
 * time budget, and QuickJS's interrupt handler, which it polls every ten
 * thousand or so operations, stops the code once the budget is spent. The
 * error it throws cannot be caught, so a script cannot swallow it and keep
 * looping. The budget belongs to the outermost entry: an event a script
 * dispatches from inside its own run spends the run's budget rather than
 * starting a fresh one, or nesting would make the limit meaningless.
 *
 * The clock comes from the browser, as a function pointer, because this
 * library has no system calls of its own. One page runs at a time, so the
 * state is process wide, as the listener table already is. */
static uint64_t (*g_clock)(void);
static int64_t (*g_wall)(void);
static uint64_t g_budget_ms;
static uint64_t g_deadline;
static int g_depth;
static int g_stopped;

static int njs_interrupt(JSRuntime *rt, void *opaque) {
    (void)rt; (void)opaque;
    if (!g_deadline || !g_clock || g_clock() <= g_deadline) return 0;
    g_stopped = 1;
    return 1;
}

/* The clocks the browser lends: `clock` is monotonic milliseconds, the one
 * the time budget is kept on and performance.now() reads; `wall` is Unix
 * milliseconds, the one Date reads. Lent before a context is made, because
 * making one seeds Math.random from the wall clock and fixes the moment
 * performance.now() counts from. With none lent both read zero, which is
 * what a page would see on a machine whose clock was never set. */
void njs_set_clocks(uint64_t (*clock)(void), int64_t (*wall)(void)) {
    g_clock = clock;
    g_wall = wall;
}

/* Read by cutils.h (NJS_HOST_CLOCKS) for Date and the Math.random seed. */
int64_t njs_wall_us(void) {
    return g_wall ? g_wall() * 1000 : 0;
}

/* Read by cutils.h (NJS_HOST_CLOCKS) for performance.now(). */
uint64_t njs_mono_ns(void) {
    return g_clock ? g_clock() * 1000000ULL : 0;
}

/* Bound the runtime's heap and stack and arm the time budget, kept on the
 * clock njs_set_clocks lent. */
void njs_set_limits(JSRuntime *rt, size_t memory, size_t stack, uint64_t budget_ms) {
    JS_SetMemoryLimit(rt, memory);
    JS_SetMaxStackSize(rt, stack);
    g_budget_ms = budget_ms;
    JS_SetInterruptHandler(rt, njs_interrupt, NULL);
}

/* The budget for the entries that follow, the limits otherwise as they
 * were set. An entry already running keeps the deadline it started with. */
void njs_set_budget(uint64_t budget_ms) {
    g_budget_ms = budget_ms;
}

/* Entering the engine from the browser. Only the outermost entry anchors
 * the stack limit and starts the clock: anchoring again from a nested
 * entry would hand the inner code a whole new stack allowance below the
 * outer one's, which is how a bounded stack overflows anyway. */
void njs_enter(JSRuntime *rt) {
    if (g_depth++ > 0) return;
    JS_UpdateStackTop(rt);
    g_deadline = (g_clock && g_budget_ms) ? g_clock() + g_budget_ms : 0;
}

/* Whether the outermost entry has spent its budget: a dispatch stops
 * calling listeners then, and a job queue stops running jobs, rather than
 * starting each only to stop it. Work left unrun for this counts as a
 * stop: a promise chain that requeues itself forever is made of jobs too
 * short for the interrupt handler ever to be polled inside one. */
int njs_over_budget(void) {
    if (!g_deadline || !g_clock || g_clock() <= g_deadline) return 0;
    g_stopped = 1;
    return 1;
}

void njs_leave(void) {
    if (g_depth > 0 && --g_depth == 0) g_deadline = 0;
}

/* Whether code was stopped for running past its budget since the last
 * call. Reading clears it, so one stop is reported once. */
int njs_take_stopped(void) {
    int s = g_stopped;
    g_stopped = 0;
    return s;
}
JSContext *njs_new_context(JSRuntime *rt) { return JS_NewContext(rt); }
extern void njs_drop_listeners(JSContext *ctx);
void njs_free_context(JSContext *ctx) {
    njs_drop_listeners(ctx);
    JS_FreeContext(ctx);
}
void njs_free_runtime(JSRuntime *rt) { JS_FreeRuntime(rt); }

/* Evaluate `code` and return a malloc'd string: the result coerced to string,
 * or the exception message. The caller frees it. Pending jobs (resolved
 * promises, queued microtasks) are drained first. */
char *njs_eval_to_string(JSContext *ctx, const char *code, size_t len) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    /* Re-anchor the stack limit to this native frame. The runtime captures its
     * stack top at creation, which may sit far above the frame a page script
     * actually evaluates from (the render loop), so without this a shallow
     * script can trip a false stack-overflow. */
    njs_enter(rt);
    /* JS_Eval requires input[len] == '\0'. The caller passes a Rust &str, which
     * is not NUL-terminated, so copy into a terminated buffer; otherwise the
     * lexer reads past the source and faults on a page boundary. */
    char *src = (char *)malloc(len + 1);
    if (!src) {
        njs_leave();
        return dup_cstr("out of memory");
    }
    for (size_t i = 0; i < len; i++) src[i] = code[i];
    src[len] = 0;
    JSValue v = JS_Eval(ctx, src, len, "<nonos>", JS_EVAL_TYPE_GLOBAL);
    free(src);
    JSContext *pending;
    while (!njs_over_budget() && JS_ExecutePendingJob(rt, &pending) > 0) {}
    njs_leave();
    char *out;
    if (JS_IsException(v)) {
        JSValue e = JS_GetException(ctx);
        const char *s = JS_ToCString(ctx, e);
        out = dup_cstr(s ? s : "exception");
        JS_FreeCString(ctx, s);
        JS_FreeValue(ctx, e);
    } else {
        const char *s = JS_ToCString(ctx, v);
        out = dup_cstr(s ? s : "");
        JS_FreeCString(ctx, s);
    }
    JS_FreeValue(ctx, v);
    return out;
}
