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
- [x] `CssValue` enum: Length, Color, Keyword, Number, Percentage, Auto, None, Inherit, Initial
- [x] `Unit` enum: Px, Em, Rem, Percent, Vw, Vh, Pt
- [x] Color parsing: named colors, `#rgb`, `#rrggbb`, `rgb()`, `rgba()`
- [x] Tokenizer: ident, hash, string, number, dimension, delim, whitespace, punctuation
- [x] `CssError` enum with `as_str()`, `code()`, `is_recoverable()`

**Parser:**
- [x] Parse `<style>` block content → `Stylesheet` (Vec of Rules)
- [x] Parse inline `style=""` → `Vec<Declaration>`
- [x] Selectors: type, class, id, universal, attribute, pseudo-classes
- [x] Combinators: descendant, child, adjacent, general sibling
- [x] Compound selectors (`.foo.bar#baz`)
- [x] `@media` queries: store rules, evaluate viewport match
- [x] Shorthand expansion: margin, padding, border, background, font

**Cascade & Inheritance:**
- [x] `ComputedStyle` struct: all resolved CSS properties with typed values
- [x] Default style for each property (CSS initial values)
- [x] Inheritance table: color/font-size inherit, margin/padding don't
- [x] Specificity: `(inline, id, class, type)` with `Ord`
- [x] Cascade: origin, specificity, order, `!important`
- [x] Selector matching: given node + ancestors, which selectors match?
- [x] `resolve_style(node, parent_computed, stylesheets) -> ComputedStyle`
- [x] Unit resolution: em/rem/% → px
- [x] CSS custom properties + `var()` resolution

**Stylesheet Loading:**
- [x] HTML parser: extract `<style>` blocks, collect `<link rel="stylesheet">` URLs
- [x] Replace `parse_hidden_classes()` with real CSS cascade

**Tests:**
- [x] Tokenizer: simple rules, complex selectors, edge cases
- [x] Parser: single rule, multiple rules, nested selectors, media queries, shorthands
- [x] Selector matching: `.foo` matches `<div class="foo">`, combinators
- [x] Specificity ordering: `(0,0,1) < (0,1,0) < (1,0,0)`
- [x] Cascade: higher specificity wins, same specificity → later wins
- [x] Inheritance: child inherits color, not margin
- [x] Computed style: `2em` on parent `font-size:16px` → `32px`
- [x] `cargo test` + `cargo build` (bare metal) pass

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
- [x] `LayoutBox`: box_type, dimensions, children, style, node_id
- [x] `Dimensions`: content Rect + padding/border/margin EdgeSizes
- [x] `padding_box()`, `border_box()`, `margin_box()` helpers
- [x] `build_layout_tree(dom, styles) -> LayoutBox`

**Block Layout:**
- [x] Block children stack vertically
- [x] Width: auto margins, explicit width, min/max constraints
- [x] Height: explicit or sum of children
- [x] Vertical margin collapsing
- [x] Anonymous block boxes for mixed inline/block content
- [x] `display: inline-block`

**Inline Layout:**
- [x] Line boxes: left-to-right flow, wrap at container width
- [x] Word breaking at whitespace
- [x] `text-align`: left, center, right, justify
- [x] `line-height` spacing

**Flexbox:**
- [x] `flex-direction`, `flex-wrap`, `justify-content`, `align-items`
- [x] `flex-grow`, `flex-shrink`, `flex-basis`
- [x] Main axis: distribute free space / shrink overflow
- [x] Cross axis alignment
- [x] Multi-line wrapping

**Positioning:**
- [x] `relative`: offset from normal flow
- [x] `absolute`: relative to positioned ancestor
- [x] `fixed`: relative to viewport
- [x] `float`/`clear`
- [x] `z-index` stacking contexts
- [x] `overflow: hidden/scroll/auto`

**Integration:**
- [x] `render_page()`: parse → style → layout → paint
- [x] Backward compat: `render_to_lines()` still works
- [x] `RenderOutput` extended with layout tree for hit testing

**Tests:**
- [x] Box model: padding/border/margin calculations
- [x] Block: three divs stack vertically, fill width
- [x] Inline: text wraps at viewport width
- [x] Flexbox: row layout, flex-grow, justify-content center
- [x] Positioning: absolute at correct coords
- [x] Margin collapsing
- [x] `cargo test` + `cargo build` pass

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
- [x] `NodeId` newtype: u32 index
- [x] `DomArena`: Vec<DomNode>, access by NodeId
- [x] `DomNode`: id, node_type, tag, attributes, parent, children, siblings, text
- [x] `create_element(tag) -> NodeId`
- [x] `create_text_node(text) -> NodeId`
- [x] `append_child`, `remove_child`, `insert_before`, `replace_child`
- [x] Convert HTML parser `Document` → `DomArena`

**Query:**
- [x] `get_element_by_id(id) -> Option<NodeId>`
- [x] `get_elements_by_class_name(class) -> Vec<NodeId>`
- [x] `get_elements_by_tag_name(tag) -> Vec<NodeId>`
- [x] `query_selector(selector) -> Option<NodeId>` (uses CSS selector matcher)
- [x] `query_selector_all(selector) -> Vec<NodeId>`

**JS Bridge:**
- [x] `JsDocument` holds `Rc<RefCell<DomArena>>`
- [x] All document.* methods → real arena operations
- [x] `element.appendChild()` → `arena.append_child()` + mark dirty
- [x] `element.innerHTML` setter → parse fragment, replace children
- [x] `element.textContent` get/set
- [x] `element.setAttribute`/`getAttribute`
- [x] `classList`: add, remove, toggle, contains
- [x] `element.style` → CSSStyleDeclaration proxy
- [x] `getBoundingClientRect()` → read from layout tree

**Dirty Tracking:**
- [x] Any DOM mutation sets `needs_layout = true`
- [x] Before `getBoundingClientRect()` or paint: relayout if dirty
- [x] Batch mutations → single relayout

**Tests:**
- [x] Arena: create, append, verify parent/child/sibling links
- [x] Remove/insert: siblings update correctly
- [x] Query: getElementById finds node, querySelectorAll returns matches
- [x] JS: createElement + appendChild → node in arena
- [x] innerHTML: set → parses, replaces children
- [x] classList: add/remove/toggle/contains roundtrip
- [x] `cargo test` + `cargo build` pass

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
- [x] `DomEvent`: type, target, current_target, phase, bubbles, cancelable, timestamps
- [x] `preventDefault()`, `stopPropagation()`, `stopImmediatePropagation()`
- [x] `MouseEvent`: client_x, client_y, button
- [x] `KeyboardEvent`: key, code, ctrl/shift/alt/meta
- [x] `InputEvent`: data, input_type
- [x] `FocusEvent`: related_target
- [x] `EventListener`: callback, capture, once, passive

**Dispatch:**
- [x] Build path: target → ancestors → document
- [x] Capture phase: root → target, call capture listeners
- [x] Target phase: call all listeners on target
- [x] Bubble phase: target → root (if bubbles)
- [x] stopPropagation stops traversal
- [x] stopImmediatePropagation stops current node
- [x] After dispatch: execute default action if not prevented

**Input Wiring:**
- [x] Click: (x,y) → hit test layout tree → dispatch MouseEvent
- [x] Keyboard: keydown/keyup → dispatch to focused element
- [x] Focus: focus()/blur() update activeElement, dispatch focus events
- [x] Lifecycle: DOMContentLoaded after parse, load after resources

**Tests:**
- [x] Event reaches target, bubbles to parent
- [x] stopPropagation stops bubble
- [x] Capture fires before bubble
- [x] preventDefault sets flag
- [x] once listener auto-removes
- [x] Hit testing maps coords to correct node
- [x] focus() sets activeElement
- [x] `cargo test` + `cargo build` pass

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
- [x] Property lookup: own → __proto__ → chain until null
- [x] `new Foo()`: create obj, set proto, call constructor with this
- [x] `instanceof`: walk proto chain
- [x] Built-in prototypes: Array, String, Number, Object
- [x] Method resolution on primitives: `"hello".toUpperCase()`

**Closures & Scope:**
- [x] Lexical scoping: function captures enclosing scope
- [x] Scope chain: parent links, walk outward for lookup
- [x] `let`/`const` block scope, `var` hoisting
- [x] `this` binding: method, arrow, call/apply/bind
- [x] IIFE pattern works

**Promises & Async:**
- [x] Promise states: Pending, Fulfilled, Rejected
- [x] `.then()` → enqueue microtask, return new Promise
- [x] `.catch()`, `.finally()`
- [x] `Promise.resolve/reject/all/race`
- [x] `async function` returns Promise
- [x] `await` suspends, resumes on settlement
- [x] `queueMicrotask()`

**Timers & Event Loop:**
- [x] `setTimeout(cb, delay)` → enqueue macrotask
- [x] `setInterval(cb, delay)` → recurring macrotask
- [x] `clearTimeout`/`clearInterval`
- [x] `requestAnimationFrame`
- [x] Event loop: drain stack → drain microtasks → fire one timer

**Builtins:**
- [x] Error/TypeError/RangeError/SyntaxError/ReferenceError
- [x] try/catch/finally execution
- [x] `Map`, `Set`
- [x] `Symbol`, `Symbol.iterator`, `for...of`
- [x] Basic RegExp execution: `.test()`, `.exec()`
- [x] Destructuring: object + array
- [x] Spread, template literals, optional chaining, nullish coalescing

**Tests:**
- [x] Proto chain: `obj.toString()` resolves from Object.prototype
- [x] Closures: counter closure increments
- [x] this: method call, arrow, call/apply/bind
- [x] Promise: resolve/reject, chaining, Promise.all
- [x] async/await: returns promise, await resolves
- [x] setTimeout fires, clearTimeout cancels
- [x] try/catch: catches thrown error, finally runs
- [x] `cargo test` + `cargo build` pass

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
- [x] `fetch(url, options)` returns Promise
- [x] Wire to `request::fetch_page()` for HTTP
- [x] Response: `.status`, `.ok`, `.headers`, `.json()`, `.text()`
- [x] Request constructor, Headers object
- [x] Respect CORS (Phase 7 hook point)

**URL & FormData:**
- [x] URL: parse, expose href/origin/protocol/host/pathname/search/hash/searchParams
- [x] URLSearchParams: get/set/append/delete/toString/iterable
- [x] FormData: append/get/getAll/has/delete/entries

**History/Location/Navigator:**
- [x] `history.pushState/replaceState/back/forward/go`
- [x] `popstate` event on navigation
- [x] `location`: href, origin, assign(), replace(), reload()
- [x] `navigator`: userAgent, language, onLine, cookieEnabled

**Storage:**
- [x] localStorage/sessionStorage: getItem/setItem/removeItem/clear/length
- [x] Wire to existing `session::storage`

**Utilities:**
- [x] `crypto.getRandomValues()` → kernel CSPRNG
- [x] `TextEncoder`/`TextDecoder` → UTF-8
- [x] `atob()`/`btoa()` → base64
- [x] `performance.now()` → kernel timer
- [x] `AbortController`/`AbortSignal`
- [x] `MutationObserver`, `IntersectionObserver`, `ResizeObserver`

**Tests:**
- [x] Fetch resolves with response, .json() parses
- [x] URL parses all components
- [x] URLSearchParams roundtrip
- [x] pushState changes URL, popstate fires on back()
- [x] localStorage set/get roundtrip
- [x] TextEncoder/TextDecoder roundtrip
- [x] btoa/atob roundtrip
- [x] `cargo test` + `cargo build` pass

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
- [x] `Origin` struct: scheme, host, port
- [x] `same_origin(a, b) -> bool`
- [x] Cookie/storage scoped to origin
- [x] Cross-origin fetch rejected by default

**CORS:**
- [x] Simple requests: send `Origin`, check `Access-Control-Allow-Origin`
- [x] Preflight: OPTIONS + `Access-Control-Request-Method/Headers`
- [x] Validate: Allow-Origin, Allow-Methods, Allow-Headers, Allow-Credentials
- [x] `Access-Control-Expose-Headers` limits visible response headers
- [x] Wire into fetch pipeline

**CSP:**
- [x] Parse `Content-Security-Policy` header
- [x] Parse `<meta http-equiv="Content-Security-Policy">`
- [x] Directives: default-src, script-src, style-src, img-src, connect-src
- [x] Source expressions: 'self', 'unsafe-inline', 'unsafe-eval', 'none', nonce, hash
- [x] Enforce before loading resources
- [x] Report-only mode

**XSS & Mixed Content:**
- [x] innerHTML sanitization for `<script>` tags
- [x] HTTPS page blocks HTTP sub-resources
- [x] `X-Content-Type-Options: nosniff`
- [x] Referrer-Policy enforcement

**Tests:**
- [x] Same origin: same scheme+host+port passes, different fails
- [x] CORS: cross-origin without headers → blocked
- [x] CORS: with `Allow-Origin: *` → allowed
- [x] Preflight: non-simple sends OPTIONS first
- [x] CSP: `script-src 'self'` blocks inline, allows same-origin
- [x] Mixed content: HTTPS page + HTTP image → blocked
- [x] `cargo test` + `cargo build` pass

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
- [x] Parse `Strict-Transport-Security` header
- [x] Cache with expiration
- [x] Upgrade HTTP → HTTPS on cached domains

**SRI:**
- [x] Parse `integrity` attribute
- [x] Hash fetched resource (SHA-256/384/512)
- [x] Block on mismatch

**HTTP/2:**
- [x] Frame types: DATA, HEADERS, SETTINGS, PING, GOAWAY, WINDOW_UPDATE
- [x] HPACK: static table, dynamic table, Huffman coding
- [x] Stream multiplexing over single TCP
- [x] Flow control: window updates
- [x] ALPN negotiation in TLS handshake
- [x] Fallback to HTTP/1.1

**Compression:**
- [x] Chunked transfer encoding parsing
- [x] gzip decompression (verify existing)
- [x] Brotli: enable by default
- [x] `Accept-Encoding: gzip, deflate, br` on all requests

**Tests:**
- [x] HSTS: header parsed, cache stores, HTTP upgraded
- [x] SRI: matching hash passes, mismatch blocks
- [x] HTTP/2: encode/decode DATA, HEADERS, SETTINGS frames
- [x] HPACK: static table, dynamic table, Huffman roundtrip
- [x] Chunked encoding parsed correctly
- [x] `cargo test` + `cargo build` pass

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

- [x] Font metrics: char width/height/ascent/descent
- [x] Font matching: font-family → best available
- [x] Built-in font metric tables
- [x] @font-face parsing + loading
- [x] SVG: text, gradients, transforms, full path `d` parsing
- [x] Canvas 2D: paths, drawing, styles, gradients, text, images, pixels, transforms, state stack
- [x] Video/audio: API surface only, `.play()` returns error

**Tests:**
- [x] Font metrics: monospace width × chars = line width
- [x] SVG: gradient parsing, transform, path d
- [x] Canvas: path ops, gradient interpolation
- [x] Video stub: .play() doesn't crash
- [x] `cargo test` + `cargo build` pass

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

- [x] AccessibleNode, AriaRole enum (~25 roles)
- [x] Build a11y tree from DOM: implicit + explicit roles
- [x] ARIA: aria-label, aria-labelledby, aria-describedby, aria-hidden, aria-live
- [x] Tab order: tabindex sorting, natural focusable elements
- [x] Tab/Shift+Tab cycle, focus ring
- [x] Enter/Space → click on focused button
- [x] Text linearization from a11y tree
- [x] Live region announcements
- [x] High contrast + prefers-reduced-motion media queries

**Tests:**
- [x] `<button>` → Button role, `<nav>` → Navigation role
- [x] `role="button"` overrides implicit
- [x] aria-label sets accessible name
- [x] Tab cycles focusable elements in order
- [x] tabindex=-1 not reachable by Tab
- [x] Enter on button dispatches click
- [x] `cargo test` + `cargo build` pass

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
