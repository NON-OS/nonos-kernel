/* NONOS Operating System
 * Copyright (C) 2026 NONOS Contributors
 * SPDX-License-Identifier: AGPL-3.0
 *
 * Dispatching a UI event from the host through a node and its ancestors.
 */

/* Dispatch a UI event to a node's listeners, then bubble through its
 * ancestors: frameworks that delegate (React listens on the root container)
 * see the event with target still pointing at the origin node. Callable from
 * the host when a real pointer/key event lands on a laid-out node. Drains the
 * job queue so listener-scheduled microtasks settle before layout. */
static int run_dispatch(JSContext *ctx, int node, const char *type, JSValue ev);

int njs_dispatch_event(JSContext *ctx, int node, const char *type) {
    njs_enter(JS_GetRuntime(ctx));
    int fired = run_dispatch(ctx, node, type, make_event(ctx, node, type));
    njs_leave();
    return fired;
}

/* The walk itself, over an event already built (make_event, and what
 * dom_ui_event.inc adds for a key or a pointer). Takes `ev` and frees it.
 * The caller has entered the engine. */
static int run_dispatch(JSContext *ctx, int node, const char *type, JSValue ev) {
    void *host = JS_GetContextOpaque(ctx);
    int fired = 0;
    int hops = 0;
    /* A listener that spent the budget leaves the rest unrun: each would
     * only be started to be stopped. */
    for (int cur = node; cur >= 0 && hops < 512 && !njs_over_budget();
         cur = njs_dom_parent(host, cur), hops++) {
        JSValue self = make_element(ctx, cur);
        JS_SetPropertyStr(ctx, ev, "currentTarget", JS_DupValue(ctx, self));
        /* The on<type> property is a listener too. It was set to null on
         * every element and then never read, so `el.onclick = fn` looked
         * like it had registered and nothing ever called it. */
        char prop[32];
        prop[0] = 'o'; prop[1] = 'n';
        int pi = 0;
        for (; type[pi] && pi < 28; pi++) prop[pi + 2] = type[pi];
        prop[pi + 2] = 0;
        JSValue handler = JS_GetPropertyStr(ctx, self, prop);
        if (JS_IsFunction(ctx, handler)) {
            JSValue arg = ev;
            JSValue r = JS_Call(ctx, handler, self, 1, (JSValueConst *)&arg);
            settle(ctx, r);
            fired++;
        }
        JS_FreeValue(ctx, handler);
        for (int i = 0; i < g_lcount && !ev_flag(ctx, ev, "__stopnow") && !njs_over_budget(); i++) {
            if (g_listeners[i].live && g_listeners[i].ctx == ctx && g_listeners[i].node == cur && type_eq(g_listeners[i].type, type)) {
                /* Listener `this` is the element it registered on; delegated
                 * handlers (Preact's eventProxy) read their table off it. */
                JSValue arg = ev;
                JSValue r = JS_Call(ctx, g_listeners[i].fn, self, 1, (JSValueConst *)&arg);
                settle(ctx, r);
                fired++;
            }
        }
        JS_FreeValue(ctx, self);
        /* A handler that stopped propagation meant it: the ancestors above
         * this one do not see the event at all. */
        if (ev_flag(ctx, ev, "__stop")) break;
        if (cur == 0) break;
    }
    /* Document-level listeners registered through document.addEventListener
     * carry node -1 and fire last, as the outermost bubble stop. */
    for (int i = 0; i < g_lcount && !ev_flag(ctx, ev, "__stop") && !njs_over_budget(); i++) {
        if (g_listeners[i].live && g_listeners[i].ctx == ctx && g_listeners[i].node == -1 && type_eq(g_listeners[i].type, type)) {
            JSValue arg = ev;
            JSValue r = JS_Call(ctx, g_listeners[i].fn, JS_UNDEFINED, 1, (JSValueConst *)&arg);
            settle(ctx, r);
            fired++;
        }
    }
    /* Then document.on<type> and window, the last stops of a bubble. A
     * listener added with window.addEventListener was kept and never
     * called for a click or an input, so a page that closes its menus on
     * a click anywhere, as most do, never closed them. */
    if (!ev_flag(ctx, ev, "__stop") && !njs_over_budget()) {
        JSValue global = JS_GetGlobalObject(ctx);
        JSValue out = JS_GetPropertyStr(ctx, global, "__njs_bubble_out");
        if (JS_IsFunction(ctx, out)) {
            JSValue arg = ev;
            JSValue r = JS_Call(ctx, out, JS_UNDEFINED, 1, (JSValueConst *)&arg);
            int n = 0;
            if (!JS_IsException(r)) JS_ToInt32(ctx, &n, r);
            fired += n;
            settle(ctx, r);
        }
        JS_FreeValue(ctx, out);
        JS_FreeValue(ctx, global);
    }
    g_last_prevented = ev_flag(ctx, ev, "defaultPrevented");
    JS_FreeValue(ctx, ev);
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSContext *p;
    while (!njs_over_budget() && JS_ExecutePendingJob(rt, &p) > 0) {}
    return fired;
}
