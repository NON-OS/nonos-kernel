/* NONOS Operating System
 * Copyright (C) 2026 NONOS Contributors
 * SPDX-License-Identifier: AGPL-3.0
 *
 * addEventListener, and the flags an event carries through a dispatch.
 */

static JSValue el_add_listener(JSContext *ctx, JSValueConst t, int argc, JSValueConst *v) {
    if (argc < 2) return JS_UNDEFINED;
    const char *type = JS_ToCString(ctx, v[0]);
    int i = 0;
    while (i < g_lcount && g_listeners[i].live) i++;
    if (i < MAX_LISTENERS) {
        if (i == g_lcount) g_lcount++;
        g_listeners[i].ctx = ctx;
        g_listeners[i].node = node_of(ctx, t);
        int k = 0;
        while (type[k] && k < 23) {
            g_listeners[i].type[k] = type[k];
            k++;
        }
        g_listeners[i].type[k] = 0;
        g_listeners[i].fn = JS_DupValue(ctx, v[1]);
        g_listeners[i].live = 1;
    }
    JS_FreeCString(ctx, type);
    return JS_UNDEFINED;
}

/* Event types compare case-insensitively: frameworks that probe for
 * on<type> host properties before lowercasing register mixed-case names. */
static int type_eq(const char *a, const char *b) {
    int i = 0;
    for (;; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
        if (x == 0) return 1;
    }
}

/* An event's own methods have to record something. These were no-ops, so a
 * handler that cancelled a link still navigated and one that stopped
 * propagation still saw the event reach every ancestor above it. Both are
 * how an interactive page keeps control of what it just handled. */
static JSValue ev_prevent(JSContext *ctx, JSValueConst t, int argc, JSValueConst *v) {
    (void)argc; (void)v;
    JSValue c = JS_GetPropertyStr(ctx, t, "cancelable");
    if (JS_ToBool(ctx, c) > 0)
        JS_SetPropertyStr(ctx, t, "defaultPrevented", JS_TRUE);
    JS_FreeValue(ctx, c);
    return JS_UNDEFINED;
}
static JSValue ev_stop(JSContext *ctx, JSValueConst t, int argc, JSValueConst *v) {
    (void)argc; (void)v;
    JS_SetPropertyStr(ctx, t, "__stop", JS_TRUE);
    return JS_UNDEFINED;
}
static JSValue ev_stop_now(JSContext *ctx, JSValueConst t, int argc, JSValueConst *v) {
    (void)argc; (void)v;
    JS_SetPropertyStr(ctx, t, "__stop", JS_TRUE);
    JS_SetPropertyStr(ctx, t, "__stopnow", JS_TRUE);
    return JS_UNDEFINED;
}
static int ev_flag(JSContext *ctx, JSValueConst ev, const char *name) {
    JSValue v = JS_GetPropertyStr(ctx, ev, name);
    int set = JS_ToBool(ctx, v) > 0;
    JS_FreeValue(ctx, v);
    return set;
}
