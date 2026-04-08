# NONOS Browser Engine — Implementation Plan

**Branch:** `feature/browser-engine-implementation`
**Issues:** #57-#67 (F-027 through F-037)
**Approach:** First principles, dependency-ordered phases, test-driven

---

## Engineering Philosophy: Think & Code Like Jon Gjengset

| Principle | In Practice |
|-----------|-------------|
| **Type-driven design** | Make invalid states unrepresentable. If a `Selector` can't be empty, don't let the type allow it. Enums over booleans. Newtypes over raw primitives. |
| **First principles** | Before writing code, ask: what is the *minimum correct abstraction*? A CSS cascade is a sort-by-specificity. A layout is constraint solving. A DOM is an arena. Start from the core algorithm, not from "what does Chrome do." |
| **Let the compiler work** | If it compiles, it should be correct. Encode invariants in types. Use exhaustive matches. No `unwrap()`. No `as` casts without thought. |
| **Zero-cost abstractions** | Newtypes, enums, and traits are free. Use them liberally. But don't add a trait until you have two implementations. |
| **Ownership tells the story** | Who owns the DOM? The arena. Who borrows it? JS through Rc<RefCell<>>. Who mutates it? Only through arena methods. The borrow checker is your architecture reviewer. |
| **Test the contract, not the implementation** | Test "cascade picks higher specificity" not "internal sort vector has length 3." Tests should survive refactors. |
| **No magic, no cleverness** | Boring code that works > clever code that surprises. A 5-line match > a macro. A named function > a closure chain. |
| **Ship increments** | Each phase is a shippable state. Don't design for Phase 10 in Phase 1. YAGNI until you actually need it. |

---

## Code Standards (Enforced Everywhere)

| Rule | Detail |
|------|--------|
| **No comments** | Zero comments in code. No inline, no block, no doc comments. Function and variable names must be self-explanatory. |
| **Max 75-90 lines/file** | Target 75 lines. Hard cap at 90. If approaching limit, extract into a new file. |
| **Single responsibility** | One file = one concern. Split aggressively. |
| **Self-explanatory names** | If you want to write a comment, rename the function/variable instead. |
| **No license headers** | License is in LICENSE file. Don't repeat it in every source file. |
| **Proper modularity** | Each module gets its own directory with `mod.rs` + focused implementation files. |

### File Structure Template

```
subsystem/
  mod.rs          — pub mod declarations + pub use re-exports only (~10-30 lines)
  types.rs        — structs, enums, constants (~50-75 lines per type group)
  error.rs        — error enum with as_str(), code(), is_recoverable()
  <verb>.rs       — one operation per file (parse.rs, resolve.rs, match.rs, etc.)
  tests/
    mod.rs         — #[cfg(test)] test submodules
    test_<what>.rs — focused test files (~50-75 lines each)
```

### Splitting Guidelines

| If a file has... | Split into... |
|-----------------|---------------|
| 2+ structs with methods | One file per struct |
| A match with 5+ arms, each >5 lines | Dispatch file + one file per arm |
| Parse + validate + transform | 3 files: parse.rs, validate.rs, transform.rs |
| Public API + internal helpers | api.rs + helpers.rs |
| Tests growing beyond 50 lines | Dedicated test_<topic>.rs files |

---

## Executive Summary

The NONOS browser has 154 files but is architecturally hollow. This plan rebuilds from the rendering pipeline up:

```
Bytes → Tokens → DOM Tree → CSSOM → Style Resolution → Layout Tree → Paint
```

Each phase produces a working, testable increment. No phase depends on a later phase.

---

## Current State Assessment

| Component | Files | Status | Reality |
|-----------|-------|--------|---------|
| HTML Parser | 6 | Working | Produces DOM tree with attributes |
| CSS Engine | 1 | Stub | Only detects `display:none` class names |
| Layout Engine | 8 | Flat | Text stream, no box model |
| DOM API | 4 | Mock | Every method returns null/empty |
| Event System | 1 | Empty | File exists, zero code |
| JS Runtime | 43 | Partial | Lexer+parser work, evaluator basic |
| Web APIs | 7 | Stubs | Fetch returns mock |
| Security | 0 | Absent | No CORS, CSP, SOP |
| Network | 28 | HTTP/1.1 | Works but no HTTP/2, HSTS |
| Media | 29 | Partial | PNG/JPEG decode, SVG basic |
| Accessibility | 0 | Absent | ARIA parsed as generic attrs |
| Tests | 9/154 | 6% | Only JPEG, HTML parser, forms |

---

## Phase Dependency Graph

```
Phase 1: CSS Engine (F-028) ──→ Phase 2: Layout (F-027) ──→ Phase 3: DOM (F-029)
    ──→ Phase 4: Events (F-030) ──→ Phase 5: JS Runtime (F-031)
    ──→ Phase 6: Web APIs (F-032)

Phase 7: Security (F-033)    — cross-cutting, needs DOM+Fetch
Phase 8: Network (F-034)     — independent, additive
Phase 9: Rendering (F-035)   — enhancement layer
Phase 10: Accessibility (F-036) — builds on DOM+Events

Tests (F-037) woven into every phase.
```

---

## Phase 1: CSS Engine (F-028)

**Why first:** Every visual feature depends on computed styles.

### File Plan (~20 files)

```
engine/css/
  mod.rs                — module declarations + re-exports
  types.rs              — CssValue, Unit, Color enums
  error.rs              — CssError enum
  tokenizer/
    mod.rs              — pub use tokenize
    token_types.rs      — CssToken enum
    scan.rs             — scan_token() main loop
    scan_string.rs      — string/url token scanning
    scan_number.rs      — number/dimension/percentage
  parser/
    mod.rs              — pub use parse_stylesheet, parse_inline
    parse_rule.rs       — parse one CSS rule
    parse_selector.rs   — parse selector chains
    parse_declaration.rs — parse property: value pairs
    parse_media.rs      — @media query parsing
    shorthand.rs        — expand margin/padding/border/font shorthands
  selector/
    mod.rs              — pub use
    types.rs            — Selector, Specificity structs
    match_node.rs       — does selector match a DOM node?
    specificity.rs      — calculate specificity tuple
  cascade/
    mod.rs              — pub use resolve_style
    resolve.rs          — cascade algorithm: collect + sort + apply
    inherit.rs          — inherited vs non-inherited properties
    computed.rs         — ComputedStyle struct (all resolved properties)
    defaults.rs         — initial values for each CSS property
    units.rs            — em/rem/% → px resolution
  properties/
    mod.rs              — property name → property ID mapping
    layout_props.rs     — display, position, width, height, etc.
    box_props.rs        — margin, padding, border
    text_props.rs       — color, font-size, font-weight, text-align
    visual_props.rs     — background, opacity, overflow, visibility
    flex_props.rs       — flex-direction, justify-content, align-items, etc.
```

### Checklist

**Types & Tokenizer:**
- [ ] `CssValue` enum: Length, Color, Keyword, Number, Percentage, Auto, None, Inherit, Initial
- [ ] `Unit` enum: Px, Em, Rem, Percent, Vw, Vh, Pt
- [ ] Color parsing: named colors, `#rgb`, `#rrggbb`, `rgb()`, `rgba()`
- [ ] Tokenizer: ident, hash, string, number, dimension, delim, whitespace, punctuation
- [ ] `CssError` enum with `as_str()`, `code()`, `is_recoverable()`

**Parser:**
- [ ] Parse `<style>` block content → `Stylesheet` (Vec of Rules)
- [ ] Parse inline `style=""` → `Vec<Declaration>`
- [ ] Selectors: type, class, id, universal, attribute, pseudo-classes
- [ ] Combinators: descendant, child, adjacent, general sibling
- [ ] Compound selectors (`.foo.bar#baz`)
- [ ] `@media` queries: store rules, evaluate viewport match
- [ ] Shorthand expansion: margin, padding, border, background, font

**Cascade & Inheritance:**
- [ ] `ComputedStyle` struct: all resolved CSS properties with typed values
- [ ] Default style for each property (CSS initial values)
- [ ] Inheritance table: color/font-size inherit, margin/padding don't
- [ ] Specificity: `(inline, id, class, type)` with `Ord`
- [ ] Cascade: origin, specificity, order, `!important`
- [ ] Selector matching: given node + ancestors, which selectors match?
- [ ] `resolve_style(node, parent_computed, stylesheets) -> ComputedStyle`
- [ ] Unit resolution: em/rem/% → px
- [ ] CSS custom properties + `var()` resolution

**Stylesheet Loading:**
- [ ] HTML parser: extract `<style>` blocks, collect `<link rel="stylesheet">` URLs
- [ ] Replace `parse_hidden_classes()` with real CSS cascade

**Tests:**
- [ ] Tokenizer: simple rules, complex selectors, edge cases
- [ ] Parser: single rule, multiple rules, nested selectors, media queries, shorthands
- [ ] Selector matching: `.foo` matches `<div class="foo">`, combinators
- [ ] Specificity ordering: `(0,0,1) < (0,1,0) < (1,0,0)`
- [ ] Cascade: higher specificity wins, same specificity → later wins
- [ ] Inheritance: child inherits color, not margin
- [ ] Computed style: `2em` on parent `font-size:16px` → `32px`
- [ ] `cargo test` + `cargo build` (bare metal) pass

**Commit & push.**

---

## Phase 2: Layout Engine (F-027)

**Why second:** Layout turns computed styles into positioned boxes with pixel coordinates.

### File Plan (~18 files)

```
engine/layout/
  mod.rs              — pub use build_layout_tree, perform_layout
  types.rs            — LayoutBox, BoxType, Dimensions, Rect, EdgeSizes
  error.rs            — LayoutError enum
  tree/
    mod.rs            — pub use
    build.rs          — DOM + styles → layout tree
    anonymous.rs      — anonymous block box wrapping
  block/
    mod.rs            — pub use
    layout.rs         — block-level layout algorithm
    width.rs          — width calculation with auto margins
    height.rs         — height calculation, min/max constraints
    margin_collapse.rs — vertical margin collapsing
  inline/
    mod.rs            — pub use
    line_box.rs       — collect inline content into lines
    word_break.rs     — word breaking at whitespace
    text_align.rs     — left/center/right/justify
  flex/
    mod.rs            — pub use
    main_axis.rs      — main axis sizing + free space distribution
    cross_axis.rs     — cross axis alignment
    wrap.rs           — flex-wrap line breaking
  position/
    mod.rs            — pub use
    relative.rs       — position: relative offset
    absolute.rs       — position: absolute placement
    fixed.rs          — position: fixed to viewport
    float.rs          — float: left/right + clear
    stacking.rs       — z-index stacking contexts
  paint/
    mod.rs            — pub use
    background.rs     — paint background colors
    border.rs         — paint border edges
    text.rs           — paint text within content rect
    integrate.rs      — wire layout into render_page() pipeline
```

### Checklist

**Box Model:**
- [ ] `LayoutBox`: box_type, dimensions, children, style, node_id
- [ ] `Dimensions`: content Rect + padding/border/margin EdgeSizes
- [ ] `padding_box()`, `border_box()`, `margin_box()` helpers
- [ ] `build_layout_tree(dom, styles) -> LayoutBox`

**Block Layout:**
- [ ] Block children stack vertically
- [ ] Width: auto margins, explicit width, min/max constraints
- [ ] Height: explicit or sum of children
- [ ] Vertical margin collapsing
- [ ] Anonymous block boxes for mixed inline/block content
- [ ] `display: inline-block`

**Inline Layout:**
- [ ] Line boxes: left-to-right flow, wrap at container width
- [ ] Word breaking at whitespace
- [ ] `text-align`: left, center, right, justify
- [ ] `line-height` spacing

**Flexbox:**
- [ ] `flex-direction`, `flex-wrap`, `justify-content`, `align-items`
- [ ] `flex-grow`, `flex-shrink`, `flex-basis`
- [ ] Main axis: distribute free space / shrink overflow
- [ ] Cross axis alignment
- [ ] Multi-line wrapping

**Positioning:**
- [ ] `relative`: offset from normal flow
- [ ] `absolute`: relative to positioned ancestor
- [ ] `fixed`: relative to viewport
- [ ] `float`/`clear`
- [ ] `z-index` stacking contexts
- [ ] `overflow: hidden/scroll/auto`

**Integration:**
- [ ] `render_page()`: parse → style → layout → paint
- [ ] Backward compat: `render_to_lines()` still works
- [ ] `RenderOutput` extended with layout tree for hit testing

**Tests:**
- [ ] Box model: padding/border/margin calculations
- [ ] Block: three divs stack vertically, fill width
- [ ] Inline: text wraps at viewport width
- [ ] Flexbox: row layout, flex-grow, justify-content center
- [ ] Positioning: absolute at correct coords
- [ ] Margin collapsing
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 3: Live DOM Tree (F-029)

**Why third:** JS needs a real mutable tree, not BTreeMap snapshots.

### File Plan (~14 files)

```
engine/dom/
  mod.rs              — pub use DomArena, NodeId
  arena.rs            — DomArena: Vec<DomNode> arena allocator
  node.rs             — DomNode struct, DomNodeType enum
  create.rs           — create_element, create_text_node
  mutate.rs           — append_child, remove_child, insert_before, replace_child
  query.rs            — get_element_by_id, query_selector, query_selector_all
  traverse.rs         — ancestors, descendants, siblings iterators
  convert.rs          — Document (HTML parser output) → DomArena
  dirty.rs            — dirty tracking for incremental relayout
js/dom/
  document.rs         — replace mocks with arena-backed queries
  element.rs          — replace mocks with arena-backed mutations
  class_list.rs       — classList: add, remove, toggle, contains
  style_decl.rs       — CSSStyleDeclaration proxy for inline styles
```

### Checklist

**Arena:**
- [ ] `NodeId` newtype: u32 index
- [ ] `DomArena`: Vec<DomNode>, access by NodeId
- [ ] `DomNode`: id, node_type, tag, attributes, parent, children, siblings, text
- [ ] `create_element(tag) -> NodeId`
- [ ] `create_text_node(text) -> NodeId`
- [ ] `append_child`, `remove_child`, `insert_before`, `replace_child`
- [ ] Convert HTML parser `Document` → `DomArena`

**Query:**
- [ ] `get_element_by_id(id) -> Option<NodeId>`
- [ ] `get_elements_by_class_name(class) -> Vec<NodeId>`
- [ ] `get_elements_by_tag_name(tag) -> Vec<NodeId>`
- [ ] `query_selector(selector) -> Option<NodeId>` (uses CSS selector matcher)
- [ ] `query_selector_all(selector) -> Vec<NodeId>`

**JS Bridge:**
- [ ] `JsDocument` holds `Rc<RefCell<DomArena>>`
- [ ] All document.* methods → real arena operations
- [ ] `element.appendChild()` → `arena.append_child()` + mark dirty
- [ ] `element.innerHTML` setter → parse fragment, replace children
- [ ] `element.textContent` get/set
- [ ] `element.setAttribute`/`getAttribute`
- [ ] `classList`: add, remove, toggle, contains
- [ ] `element.style` → CSSStyleDeclaration proxy
- [ ] `getBoundingClientRect()` → read from layout tree

**Dirty Tracking:**
- [ ] Any DOM mutation sets `needs_layout = true`
- [ ] Before `getBoundingClientRect()` or paint: relayout if dirty
- [ ] Batch mutations → single relayout

**Tests:**
- [ ] Arena: create, append, verify parent/child/sibling links
- [ ] Remove/insert: siblings update correctly
- [ ] Query: getElementById finds node, querySelectorAll returns matches
- [ ] JS: createElement + appendChild → node in arena
- [ ] innerHTML: set → parses, replaces children
- [ ] classList: add/remove/toggle/contains roundtrip
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 4: Event System (F-030)

**Why fourth:** Events connect user input to JavaScript handlers.

### File Plan (~12 files)

```
js/dom/
  events/
    mod.rs            — pub use dispatch_event, DomEvent
    types.rs          — DomEvent, EventPhase, EventListener
    mouse.rs          — MouseEvent fields
    keyboard.rs       — KeyboardEvent fields
    input.rs          — InputEvent fields
    focus.rs          — FocusEvent fields
    dispatch.rs       — 3-phase dispatch: capture → target → bubble
    listeners.rs      — addEventListener, removeEventListener
    lifecycle.rs      — DOMContentLoaded, load, beforeunload
    hit_test.rs       — (x,y) → NodeId via layout tree
    focus_mgmt.rs     — document.activeElement, focus/blur tracking
```

### Checklist

**Event Types:**
- [ ] `DomEvent`: type, target, current_target, phase, bubbles, cancelable, timestamps
- [ ] `preventDefault()`, `stopPropagation()`, `stopImmediatePropagation()`
- [ ] `MouseEvent`: client_x, client_y, button
- [ ] `KeyboardEvent`: key, code, ctrl/shift/alt/meta
- [ ] `InputEvent`: data, input_type
- [ ] `FocusEvent`: related_target
- [ ] `EventListener`: callback, capture, once, passive

**Dispatch:**
- [ ] Build path: target → ancestors → document
- [ ] Capture phase: root → target, call capture listeners
- [ ] Target phase: call all listeners on target
- [ ] Bubble phase: target → root (if bubbles)
- [ ] stopPropagation stops traversal
- [ ] stopImmediatePropagation stops current node
- [ ] After dispatch: execute default action if not prevented

**Input Wiring:**
- [ ] Click: (x,y) → hit test layout tree → dispatch MouseEvent
- [ ] Keyboard: keydown/keyup → dispatch to focused element
- [ ] Focus: focus()/blur() update activeElement, dispatch focus events
- [ ] Lifecycle: DOMContentLoaded after parse, load after resources

**Tests:**
- [ ] Event reaches target, bubbles to parent
- [ ] stopPropagation stops bubble
- [ ] Capture fires before bubble
- [ ] preventDefault sets flag
- [ ] once listener auto-removes
- [ ] Hit testing maps coords to correct node
- [ ] focus() sets activeElement
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 5: JS Runtime Completion (F-031)

**Why fifth:** DOM + events are working; now make the JS engine execute real-world code.

### File Plan (~16 files)

```
js/runtime/
  prototype/
    mod.rs            — pub use
    chain.rs          — property lookup via proto chain
    create.rs         — Object.create, Object.getPrototypeOf
    constructor.rs    — new Foo() semantics
    builtin_protos.rs — Array/String/Number/Object prototypes
  scope/
    mod.rs            — (refactor existing scope.rs)
    chain.rs          — scope chain walking
    binding.rs        — let/const block scope, var hoisting
    this_binding.rs   — method/arrow/call/apply/bind this
  promise/
    mod.rs            — pub use
    state.rs          — Pending/Fulfilled/Rejected
    then.rs           — .then(), .catch(), .finally()
    combinators.rs    — Promise.all, Promise.race, Promise.resolve/reject
  event_loop/
    mod.rs            — pub use
    microtask.rs      — microtask queue drain
    timers.rs         — setTimeout, setInterval, clearTimeout
    tick.rs           — call stack → microtasks → one macrotask
  builtins/
    error_types.rs    — Error, TypeError, RangeError constructors
    map_set.rs        — Map, Set (BTreeMap/BTreeSet backed)
    symbol.rs         — Symbol type, Symbol.iterator
    regexp_exec.rs    — basic .test(), .exec(), .match()
```

### Checklist

**Prototypes:**
- [ ] Property lookup: own → __proto__ → chain until null
- [ ] `new Foo()`: create obj, set proto, call constructor with this
- [ ] `instanceof`: walk proto chain
- [ ] Built-in prototypes: Array, String, Number, Object
- [ ] Method resolution on primitives: `"hello".toUpperCase()`

**Closures & Scope:**
- [ ] Lexical scoping: function captures enclosing scope
- [ ] Scope chain: parent links, walk outward for lookup
- [ ] `let`/`const` block scope, `var` hoisting
- [ ] `this` binding: method, arrow, call/apply/bind
- [ ] IIFE pattern works

**Promises & Async:**
- [ ] Promise states: Pending, Fulfilled, Rejected
- [ ] `.then()` → enqueue microtask, return new Promise
- [ ] `.catch()`, `.finally()`
- [ ] `Promise.resolve/reject/all/race`
- [ ] `async function` returns Promise
- [ ] `await` suspends, resumes on settlement
- [ ] `queueMicrotask()`

**Timers & Event Loop:**
- [ ] `setTimeout(cb, delay)` → enqueue macrotask
- [ ] `setInterval(cb, delay)` → recurring macrotask
- [ ] `clearTimeout`/`clearInterval`
- [ ] `requestAnimationFrame`
- [ ] Event loop: drain stack → drain microtasks → fire one timer

**Builtins:**
- [ ] Error/TypeError/RangeError/SyntaxError/ReferenceError
- [ ] try/catch/finally execution
- [ ] `Map`, `Set`
- [ ] `Symbol`, `Symbol.iterator`, `for...of`
- [ ] Basic RegExp execution: `.test()`, `.exec()`
- [ ] Destructuring: object + array
- [ ] Spread, template literals, optional chaining, nullish coalescing

**Tests:**
- [ ] Proto chain: `obj.toString()` resolves from Object.prototype
- [ ] Closures: counter closure increments
- [ ] this: method call, arrow, call/apply/bind
- [ ] Promise: resolve/reject, chaining, Promise.all
- [ ] async/await: returns promise, await resolves
- [ ] setTimeout fires, clearTimeout cancels
- [ ] try/catch: catches thrown error, finally runs
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 6: Web APIs (F-032)

**Why sixth:** Real JS runtime + DOM + events → expose platform APIs.

### File Plan (~14 files)

```
js/api/
  fetch/
    mod.rs            — pub use
    request.rs        — Request constructor
    response.rs       — Response: status, json(), text()
    headers.rs        — Headers: get, set, has, entries
    execute.rs        — wire to kernel HTTP stack
  url/
    mod.rs            — pub use
    url.rs            — URL constructor + property accessors
    search_params.rs  — URLSearchParams: get, set, append, iterate
  form_data.rs        — FormData: append, get, entries
  history.rs          — pushState, replaceState, back, forward
  location.rs         — location object: href, origin, pathname, etc.
  navigator.rs        — navigator: userAgent, language, onLine
  storage.rs          — localStorage/sessionStorage (wire to session module)
  encoding.rs         — TextEncoder, TextDecoder, atob, btoa
  crypto.rs           — crypto.getRandomValues, crypto.subtle.digest
  observers.rs        — MutationObserver, IntersectionObserver, ResizeObserver
  performance.rs      — performance.now()
  abort.rs            — AbortController, AbortSignal
```

### Checklist

**Fetch (real):**
- [ ] `fetch(url, options)` returns Promise
- [ ] Wire to `request::fetch_page()` for HTTP
- [ ] Response: `.status`, `.ok`, `.headers`, `.json()`, `.text()`
- [ ] Request constructor, Headers object
- [ ] Respect CORS (Phase 7 hook point)

**URL & FormData:**
- [ ] URL: parse, expose href/origin/protocol/host/pathname/search/hash/searchParams
- [ ] URLSearchParams: get/set/append/delete/toString/iterable
- [ ] FormData: append/get/getAll/has/delete/entries

**History/Location/Navigator:**
- [ ] `history.pushState/replaceState/back/forward/go`
- [ ] `popstate` event on navigation
- [ ] `location`: href, origin, assign(), replace(), reload()
- [ ] `navigator`: userAgent, language, onLine, cookieEnabled

**Storage:**
- [ ] localStorage/sessionStorage: getItem/setItem/removeItem/clear/length
- [ ] Wire to existing `session::storage`

**Utilities:**
- [ ] `crypto.getRandomValues()` → kernel CSPRNG
- [ ] `TextEncoder`/`TextDecoder` → UTF-8
- [ ] `atob()`/`btoa()` → base64
- [ ] `performance.now()` → kernel timer
- [ ] `AbortController`/`AbortSignal`
- [ ] `MutationObserver`, `IntersectionObserver`, `ResizeObserver`

**Tests:**
- [ ] Fetch resolves with response, .json() parses
- [ ] URL parses all components
- [ ] URLSearchParams roundtrip
- [ ] pushState changes URL, popstate fires on back()
- [ ] localStorage set/get roundtrip
- [ ] TextEncoder/TextDecoder roundtrip
- [ ] btoa/atob roundtrip
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 7: Browser Security (F-033)

**Why here:** CORS checks need fetch. CSP checks need script loading. SOP needs DOM. All exist now.

### File Plan (~12 files)

```
security/
  mod.rs              — pub use
  types.rs            — Origin struct, SecurityError enum
  error.rs            — SecurityError: CorsBlocked, CspViolation, etc.
  origin.rs           — Origin::from_url, Origin::same_origin
  sop/
    mod.rs            — pub use
    enforce.rs        — same-origin checks for DOM, cookies, storage
  cors/
    mod.rs            — pub use
    simple.rs         — simple request: send Origin, check Allow-Origin
    preflight.rs      — OPTIONS preflight for non-simple requests
    validate.rs       — validate CORS response headers
  csp/
    mod.rs            — pub use
    parse.rs          — parse CSP header into directive set
    directives.rs     — directive types: script-src, style-src, etc.
    enforce.rs        — check before loading scripts/styles/images
    source_expr.rs    — 'self', 'unsafe-inline', nonce, hash matching
  mixed_content.rs    — block HTTP sub-resources on HTTPS pages
  referrer.rs         — Referrer-Policy enforcement
```

### Checklist

**Origin & SOP:**
- [ ] `Origin` struct: scheme, host, port
- [ ] `same_origin(a, b) -> bool`
- [ ] Cookie/storage scoped to origin
- [ ] Cross-origin fetch rejected by default

**CORS:**
- [ ] Simple requests: send `Origin`, check `Access-Control-Allow-Origin`
- [ ] Preflight: OPTIONS + `Access-Control-Request-Method/Headers`
- [ ] Validate: Allow-Origin, Allow-Methods, Allow-Headers, Allow-Credentials
- [ ] `Access-Control-Expose-Headers` limits visible response headers
- [ ] Wire into fetch pipeline

**CSP:**
- [ ] Parse `Content-Security-Policy` header
- [ ] Parse `<meta http-equiv="Content-Security-Policy">`
- [ ] Directives: default-src, script-src, style-src, img-src, connect-src
- [ ] Source expressions: 'self', 'unsafe-inline', 'unsafe-eval', 'none', nonce, hash
- [ ] Enforce before loading resources
- [ ] Report-only mode

**XSS & Mixed Content:**
- [ ] innerHTML sanitization for `<script>` tags
- [ ] HTTPS page blocks HTTP sub-resources
- [ ] `X-Content-Type-Options: nosniff`
- [ ] Referrer-Policy enforcement

**Tests:**
- [ ] Same origin: same scheme+host+port passes, different fails
- [ ] CORS: cross-origin without headers → blocked
- [ ] CORS: with `Allow-Origin: *` → allowed
- [ ] Preflight: non-simple sends OPTIONS first
- [ ] CSP: `script-src 'self'` blocks inline, allows same-origin
- [ ] Mixed content: HTTPS page + HTTP image → blocked
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 8: Network Protocols (F-034)

### File Plan (~14 files)

```
security/
  hsts.rs             — parse Strict-Transport-Security, cache, upgrade
  sri.rs              — integrity attribute hash verification
navigate/
  http2/
    mod.rs            — pub use
    frame_types.rs    — DATA, HEADERS, SETTINGS, etc.
    frame_encode.rs   — serialize frames
    frame_decode.rs   — parse frames
    hpack/
      mod.rs          — pub use
      static_table.rs — HPACK static header table
      dynamic_table.rs — HPACK dynamic table
      huffman.rs      — HPACK Huffman coding
      encode.rs       — header encoding
      decode.rs       — header decoding
    stream.rs         — stream multiplexing + flow control
    connection.rs     — connection preface, ALPN, settings exchange
  chunked.rs          — chunked transfer encoding parser
  compression.rs      — verify gzip, enable brotli default
```

### Checklist

**HSTS:**
- [ ] Parse `Strict-Transport-Security` header
- [ ] Cache with expiration
- [ ] Upgrade HTTP → HTTPS on cached domains

**SRI:**
- [ ] Parse `integrity` attribute
- [ ] Hash fetched resource (SHA-256/384/512)
- [ ] Block on mismatch

**HTTP/2:**
- [ ] Frame types: DATA, HEADERS, SETTINGS, PING, GOAWAY, WINDOW_UPDATE
- [ ] HPACK: static table, dynamic table, Huffman coding
- [ ] Stream multiplexing over single TCP
- [ ] Flow control: window updates
- [ ] ALPN negotiation in TLS handshake
- [ ] Fallback to HTTP/1.1

**Compression:**
- [ ] Chunked transfer encoding parsing
- [ ] gzip decompression (verify existing)
- [ ] Brotli: enable by default
- [ ] `Accept-Encoding: gzip, deflate, br` on all requests

**Tests:**
- [ ] HSTS: header parsed, cache stores, HTTP upgraded
- [ ] SRI: matching hash passes, mismatch blocks
- [ ] HTTP/2: encode/decode DATA, HEADERS, SETTINGS frames
- [ ] HPACK: static table, dynamic table, Huffman roundtrip
- [ ] Chunked encoding parsed correctly
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 9: Rendering & Media (F-035)

### File Plan (~12 files)

```
engine/fonts/
  mod.rs              — pub use
  metrics.rs          — FontMetrics: width, height, ascent, descent
  matching.rs         — font-family CSS → select best font
  builtin.rs          — monospace + sans-serif metric tables
  loading.rs          — @font-face: fetch + parse TTF header metrics
engine/svg/           — (extend existing)
  text.rs             — <text>, <tspan>
  gradient.rs         — linearGradient, radialGradient
  transform.rs        — translate, rotate, scale, matrix
  path.rs             — full d attribute: M, L, C, S, Q, T, A, Z
engine/canvas/
  mod.rs              — pub use
  path.rs             — beginPath, moveTo, lineTo, arc, bezierCurveTo
  draw.rs             — fill, stroke, clip
  style.rs            — fillStyle, strokeStyle, gradients
  text.rs             — fillText, strokeText, measureText
  image.rs            — drawImage
  pixel.rs            — getImageData, putImageData
  transform.rs        — translate, rotate, scale, setTransform
  state.rs            — save/restore state stack
engine/media/
  stub.rs             — <video>/<audio> API surface, returns "not supported"
```

### Checklist

- [ ] Font metrics: char width/height/ascent/descent
- [ ] Font matching: font-family → best available
- [ ] Built-in font metric tables
- [ ] @font-face parsing + loading
- [ ] SVG: text, gradients, transforms, full path `d` parsing
- [ ] Canvas 2D: paths, drawing, styles, gradients, text, images, pixels, transforms, state stack
- [ ] Video/audio: API surface only, `.play()` returns error

**Tests:**
- [ ] Font metrics: monospace width × chars = line width
- [ ] SVG: gradient parsing, transform, path d
- [ ] Canvas: path ops, gradient interpolation
- [ ] Video stub: .play() doesn't crash
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Phase 10: Accessibility (F-036)

### File Plan (~10 files)

```
engine/a11y/
  mod.rs              — pub use
  types.rs            — AccessibleNode, AriaRole enum, AccessibleState
  tree.rs             — build accessibility tree from DOM
  roles/
    mod.rs            — pub use
    implicit.rs       — <button> → Button, <a> → Link, etc.
    explicit.rs       — role="button" overrides
    aria_attrs.rs     — aria-label, aria-labelledby, aria-hidden, etc.
  focus/
    mod.rs            — pub use
    tab_order.rs      — tabindex sorting, natural focusable elements
    tab_cycle.rs      — Tab/Shift+Tab navigation
    focus_ring.rs     — visual indicator on focused element
    focus_trap.rs     — modal dialog focus trapping
  keyboard.rs         — Enter/Space → click, Escape → close, arrows
  linearize.rs        — accessibility tree → sequential text stream
  announcements.rs    — role + state announcements for screen readers
  contrast.rs         — high contrast mode, prefers-contrast, prefers-reduced-motion
```

### Checklist

- [ ] AccessibleNode, AriaRole enum (~25 roles)
- [ ] Build a11y tree from DOM: implicit + explicit roles
- [ ] ARIA: aria-label, aria-labelledby, aria-describedby, aria-hidden, aria-live
- [ ] Tab order: tabindex sorting, natural focusable elements
- [ ] Tab/Shift+Tab cycle, focus ring
- [ ] Enter/Space → click on focused button
- [ ] Text linearization from a11y tree
- [ ] Live region announcements
- [ ] High contrast + prefers-reduced-motion media queries

**Tests:**
- [ ] `<button>` → Button role, `<nav>` → Navigation role
- [ ] `role="button"` overrides implicit
- [ ] aria-label sets accessible name
- [ ] Tab cycles focusable elements in order
- [ ] tabindex=-1 not reachable by Tab
- [ ] Enter on button dispatches click
- [ ] `cargo test` + `cargo build` pass

**Commit & push.**

---

## Execution Protocol (Every Phase)

```
1. Read checklist
2. Implement — one file at a time, ≤75 lines, no comments
3. Write tests alongside implementation
4. cargo test --lib --features std --target aarch64-apple-darwin
5. cargo build --release --target x86_64-nonos.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
6. Fix failures
7. git add <specific files>
8. git commit -m "browser: <phase description>"
9. git push origin feature/browser-engine-implementation
10. Next phase
```

---

## Issue-to-Phase Mapping

| Issue | Phase | Priority |
|-------|-------|----------|
| #58 F-028: CSS Support | Phase 1 | P0 |
| #57 F-027: Layout Engine | Phase 2 | P0 |
| #59 F-029: DOM API | Phase 3 | P0 |
| #60 F-030: Event System | Phase 4 | P0 |
| #61 F-031: JS Runtime | Phase 5 | P1 |
| #62 F-032: Web APIs | Phase 6 | P1 |
| #63 F-033: Security | Phase 7 | P1 |
| #64 F-034: Network | Phase 8 | P1 |
| #65 F-035: Rendering | Phase 9 | P2 |
| #66 F-036: Accessibility | Phase 10 | P2 |
| #67 F-037: Tests | All Phases | P2 |

## Test Coverage Targets

| Phase | Cumulative Coverage |
|-------|-------------------|
| 1 | ~15% |
| 2 | ~20% |
| 3 | ~25% |
| 4 | ~28% |
| 5 | ~35% |
| 6 | ~40% |
| 7 | ~43% |
| 8 | ~47% |
| 9 | ~50% |
| 10 | ~53% |

## Risk Register

| Risk | Mitigation |
|------|------------|
| CSS parser complexity | Start with subset: simple selectors + top-20 properties |
| Flexbox edge cases | Follow CSS spec Section 9 algorithm, test real patterns |
| DOM arena Rc cycles | Arena is Vec — NodeId indices prevent cycles |
| JS proto chain perf | Cap chain depth (16). Most lookups hit own-property |
| HTTP/2 complexity | Additive — HTTP/1.1 still works, can defer |
| no_std constraints | BTreeMap for HashMap, alloc::vec, wire through kernel APIs |
| f32 restriction | SSE2 allows f32. Fallback: fixed-point i32 × 64 |
