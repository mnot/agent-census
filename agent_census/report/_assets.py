"""Static CSS and the base client-side script for the HTML report.

Kept out of :mod:`html` so that module stays under the repo's per-file line
limit; the network-table script lives in :mod:`_netscript` for the same reason.
"""

CSS = """
:root {
  color-scheme: light dark;
  /* Muted secondary text. Mixed from the system ink/paper so it tracks the OS
     theme and clears 4.5:1 in both light and dark (a fixed grey did not). */
  --muted: color-mix(in srgb, CanvasText 58%, Canvas);
  /* Warning ink: a deep amber on light paper, a brighter amber on dark so the
     calibration / robots notices stay legible either way. */
  --warn: light-dark(#b45309, #d97706);
  /* Cross-tab heat (blue). Light-blue reads under dark text on paper; a deeper
     blue reads under light text in dark mode. Set as an "R G B" triple so the
     table script can vary only the alpha. */
  --heat: 96 165 250;
}
@media (prefers-color-scheme: dark) { :root { --heat: 37 99 235; } }
* { box-sizing: border-box; }
body { margin: 0; background: Canvas; color: CanvasText;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.7rem; margin: 0 0 .25rem; }
h2 { font-size: 1.25rem; margin: 2.25rem 0 .5rem; }
a { color: inherit; }
.meta { list-style: none; padding: 0; margin: .5rem 0 1.5rem; color: var(--muted); font-size: .92rem; }
.meta li { margin: .15rem 0; }
.meta code { color: CanvasText; }
.warn { color: var(--warn); }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .92rem; }
/* Each table scrolls inside its own track, so a wide one never forces the whole
   page to scroll sideways on a narrow screen. */
.tscroll { overflow-x: auto; overscroll-behavior-x: contain; margin: .5rem 0 1rem; }
.tscroll > table { margin: 0; }
/* When a track is made focusable (only while it actually overflows) show the
   focus ring so keyboard users can tell it's selected and arrow-scroll it. */
.tscroll:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8884; vertical-align: top; }
th { font-weight: 600; border-bottom: 2px solid #8886; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
/* Heavy ink rule between column groups: datacentres | off-network, and before
   Total (and, via .stick-l below, after Kind). CanvasText so it's a black line on
   light, a white one on dark -- a deliberate step up from the row hairlines. */
.netdiv { border-left: 2px solid CanvasText; }
/* A pinned divider column sits a sub-pixel right of the non-sticky column scrolling
   behind it, leaving a ~1px Canvas sliver between that column's fill and the rule.
   A 1px CanvasText shadow just outside the left border closes it -- the rule reads
   flush against the last scrolled cell instead of with a hairline gap. */
#nettab td.netdiv.stick-r, #nettab th.netdiv.stick-r { box-shadow: -1px 0 0 0 CanvasText; }
/* Grey wash on off-network headers, as an image layer so it composites over the
   pinned cell's opaque Canvas base (a flat background-color would not). */
th.netoff { background-image: linear-gradient(#8881, #8881); }
tr.netall td { border-top: 2px solid #8887; }
/* Vertical column headers for the network columns of the kind x network cross-tab
   (not the Total column, nor the Summary table). A column no wider than its number
   is no longer stretched to fit a long network name; the header row auto-grows to
   its longest label. Phones flatten these back to horizontal (see the media query). */
th.vh { vertical-align: bottom; text-align: center; white-space: nowrap;
  padding: .5rem .35rem .3rem; }
th.vh > span { display: inline-block; writing-mode: vertical-rl;
  transform: rotate(180deg); line-height: 1.1; }
/* Cluster bands: a rotated side label vertical-centred in the band, with a heavy ink
   rule (kin to .netdiv, but horizontal) marking where a band begins. #kindtab spans
   the label over the whole band (one rowspanned cell) so a long label doesn't stretch
   the first row; #nettab keeps a per-row band cell (its script needs a uniform column)
   and so its first band row still grows to the label. Band cells drop their bottom
   hairline so no rule cuts across the label. The column is a FIXED width: WebKit
   auto-sizes a column holding a rotated (vertical writing-mode) inline-block to just
   its padding -- ~8px -- so an auto column lets the 22px label overflow across the
   divider. A fixed width reserves the space in both engines (the value matches
   #nettab's Kind sticky offset below). */
.band { text-align: center; white-space: nowrap; vertical-align: middle;
  padding: .3rem .2rem; width: 1.7rem; min-width: 1.7rem; max-width: 1.7rem;
  border-bottom: 0; border-right: 1px solid #8886;
  font-weight: 600; color: color-mix(in srgb, CanvasText 58%, Canvas); }
.band > span { display: inline-block; writing-mode: vertical-rl;
  transform: rotate(180deg); letter-spacing: .01em; }
/* The band's request-share reads at full ink and heavier weight, so the number
   stands out from the muted (58% CanvasText) category name beside it. */
.band .bandpct { color: CanvasText; font-weight: 700; }
tr.bandstart > * { border-top: 2px solid #8887; }
/* Both kind tables use SEPARATE borders. WebKit places a table cell's vertical-align
   unreliably under COLLAPSED borders -- Safari dropped the summary label onto the
   band rule -- but correctly under separate ones (which is why the cross-tab was
   always fine). border-spacing: 0 keeps the row rules looking identical. */
#kindtab { border-collapse: separate; border-spacing: 0; }
/* Pin Kind (left) and the Other / off-network / Total columns (right) while the
   named-datacentre columns scroll between them. Every cell carries an opaque base
   so a pinned column stays solid over the columns scrolling behind it; heat is a
   background-image layer on top (set inline and by _netscript). */
/* Separate borders so the pinned columns reliably paint their own group rules
   (collapsed borders drop or mis-merge on sticky cells). */
#nettab { border-collapse: separate; border-spacing: 0; }
#nettab th, #nettab td { background-color: Canvas; }
#nettab .stick-l, #nettab .stick-r { position: sticky; z-index: 2; }
#nettab .stick-l { left: 1.7rem; border-right: 2px solid CanvasText; }  /* group rule after Kind, past the band column */
#nettab .stick-r { right: 0; }  /* _netscript overrides with each column's offset */
/* The cluster-band column pins left of Kind; its 1.7rem width (shared .band rule) is
   exactly Kind's left offset above, so the two pinned columns sit flush. */
#nettab .band { position: sticky; left: 0; z-index: 2; }
#netotherhd { position: relative; }
/* Running "+N hidden" cue at the top of the pinned Other header; empty -> gone. */
.othercue { position: absolute; top: .2rem; left: 0; right: 0; text-align: center;
  font-size: .68rem; font-weight: 600; color: var(--muted); }
.othercue:empty { display: none; }
.netctl { font-size: .9rem; color: var(--muted); margin: .25rem 0 .6rem; }
.netctl select { font: inherit; margin-left: .35rem; }
/* Every cross-tab cell is clickable: a number isolates its kind (and filters by
   the column's network), the Kind label isolates the kind, and the "All kinds"
   corner clears the table filters -- so the pointer covers them all. */
#nettab td { cursor: pointer; }
/* Active-network-filter pill beside the client filter box; click / Enter / Space
   clears it (handled in the page script). */
/* Active-filter row under the search box: removable kind / network pills plus the
   prominent "Show all" reset. */
.activefilters { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem;
  margin-top: .45rem; }
.activefilters:not(:has(> :not([hidden]))) { margin-top: 0; }  /* no gap when empty */
.fchip { display: inline-block; padding: .15rem .55rem; border-radius: 999px;
  font-size: .85rem; cursor: pointer; user-select: none;
  background: color-mix(in srgb, #2563eb 16%, Canvas); border: 1px solid #2563eb88; }
.fchip[hidden], .clearfilters[hidden] { display: none; }
.fchip:focus-visible, .clearfilters:focus-visible { outline: 2px solid #2563eb;
  outline-offset: 2px; }
/* Deliberately heavier than the pills: a solid accent button so clearing the
   filter is always obvious. */
.clearfilters { font: inherit; font-size: .85rem; font-weight: 600; cursor: pointer;
  padding: .2rem .7rem; border-radius: 6px; border: 1px solid #2563eb;
  background: #2563eb; color: #fff; }
/* On a phone the cross-tab can't show every network column at readable width, so
   it folds to Kind | one chosen network | Total and the picker swaps the column
   in place (same idea as the desktop "break out" control). Desktop shows all. */
.netcolctl, .netnarrow { display: none; }
@media (max-width: 640px) {
  .netcolctl { display: inline; }
  /* Rotated headers don't pay off on a phone (the cross-tab folds to one network
     and the summary table scrolls in its track); read them flat instead. */
  th.vh > span { writing-mode: horizontal-tb; transform: none; }
  /* The fold replaces the scroll, so unpin the columns and drop the running cue.
     The band column doesn't earn its width in the one-network fold -- hide it; the
     between-band rules still group the rows. */
  #nettab .stick-l, #nettab .stick-r { position: static; }
  #nettab .band { display: none; }
  .othercue { display: none; }
  #nettab th[data-net], #nettab td[data-net] { display: none; }
  #nettab th[data-net].colshow, #nettab td[data-net].colshow { display: table-cell; }
  /* The cross-tab caption's spatial guidance describes columns the folded table
     hides, so swap it for a note about the Column picker. */
  .netwide { display: none; }
  .netnarrow { display: inline; }
  /* Keep the identity column from collapsing to a sliver of break-all mono text
     when the client table scrolls sideways; it stays readable, the row scrolls. */
  td.cid { min-width: 11rem; max-width: 16rem; }
}
tr:hover td { background: #8881; }
.badge { display: inline-block; padding: .08rem .5rem; border-radius: 999px;
  color: #fff; font-size: .8rem; font-weight: 600; white-space: nowrap; }
.tag { display: inline-block; padding: .05rem .45rem; margin: 0 .2rem .2rem 0;
  border: 1px solid transparent; border-radius: 6px; background: #8883;
  font-size: .78rem; white-space: nowrap; cursor: help; }
/* Tag colour tokens (see _TAG_TOKENS in html.py). Loud terminals are white-text
   solids; the quiet middle bands are colour-mix tints over Canvas with
   light-dark() text, so both fill and text track the reader's colour scheme. */
.tag--trust { background: #047857; color: #fff; }
.tag--trust-soft { background: color-mix(in srgb, #059669 15%, Canvas);
  border-color: #05966988; color: light-dark(#065f46, #6ee7b7); }
.tag--doubt { background: color-mix(in srgb, #eab308 18%, Canvas);
  border-color: #eab30888; color: light-dark(#854d0e, #fde68a); }
.tag--human { background: color-mix(in srgb, #64748b 14%, Canvas);
  border-color: #64748b77; color: light-dark(#334155, #cbd5e1); }
.tag--bot { background: color-mix(in srgb, #9a8866 20%, Canvas);
  border-color: #9a886688; color: light-dark(#5a4d38, #e7dcc4); }
.tag--notable { background: color-mix(in srgb, #ea580c 15%, Canvas);
  border-color: #ea580c88; color: light-dark(#9a3412, #fed7aa); }
.tag--danger { background: #dc2626; color: #fff; }
.tag--danger-deep { background: #991b1b; color: #fff; }
.tag--origin { background: color-mix(in srgb, #6366f1 14%, Canvas);
  border-color: #6366f188; color: light-dark(#3730a3, #c7d2fe); }
.tag--egress { background: color-mix(in srgb, #06b6d4 16%, Canvas);
  border-color: #06b6d488; color: light-dark(#155e75, #a5f3fc); }
.flag { cursor: help; font-style: normal; }
.blurb { color: var(--muted); margin: .15rem 0 .6rem; }
/* Lightweight affordance cue: italic + muted, so it reads as guidance, not data. */
.hint { font-style: italic; color: var(--muted); font-size: .9rem; margin: .25rem 0 .6rem; }
.hint code { font-style: normal; }
/* Req/BW share bars share the sparkline's CanvasText mix so the two glyphs in a
   row read as one family (a flat pale grey was too faint to make out). */
.bar { background: color-mix(in srgb, CanvasText 66%, Canvas); border-radius: 4px;
  height: .7rem; min-width: 2px; }
/* Stacked robots-compliance bar. Segments are flex children sized by % width;
   the track background shows through any gap. cursor:help signals the per-segment
   count tooltips. */
.rbar { display: flex; width: 6rem; height: .55rem; border-radius: 3px;
  overflow: hidden; background: #8883; cursor: help; }
.rbar > span { height: 100%; min-width: 1px; }
/* Per-client request-pattern sparkline: a fixed-width bar glyph; the whole
   column shares one time axis. Bars use a CanvasText mix so they track the
   reader's light/dark scheme, like the rest of the page. */
.spark { display: block; width: 200px; max-width: 100%; height: 26px; }
.spark rect { fill: color-mix(in srgb, CanvasText 66%, Canvas); }
.spark .sparkbase { stroke: #8884; stroke-width: 1; }
/* anywhere: probe paths are long unbroken tokens (e.g. /wp-content/.../wp_file…)
   with no spaces; without this the caption blows past max-width and drags the
   column -- and the whole table -- wider than the page. */
.spark-cap { color: var(--muted); font-size: .82rem; margin-top: .15rem;
  max-width: 200px; overflow-wrap: anywhere; }
/* Pin the request-pattern column near the sparkline's own width so the glyph
   keeps its full size and the (greedier) Tags column yields the surplus instead
   of squeezing the sparkline to a sliver. */
td.reqpat, th.reqpat { width: 220px; }
.card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem;
  word-break: break-all; }
td.cid { max-width: 26rem; }
/* Floor the identity column on desktop so a heavy Tags / evidence row can't squeeze
   it down to a sliver that wraps IPs and AS names mid-token (break-all). Scoped to
   non-phone widths so the tighter phone floor above still wins (it sits earlier in
   source order, so an unscoped rule here would override it). */
@media (min-width: 641px) { td.cid { min-width: 14rem; } }
.cid-id { font-weight: 600; }
.cid-as { color: var(--muted); font-size: .8rem; word-break: break-word; margin: 1px 0; }
.cid-ua { color: var(--muted); font-size: .82rem; margin-top: 1px;
  display: -webkit-box; -webkit-line-clamp: 3; line-clamp: 3;
  -webkit-box-orient: vertical; overflow: hidden; word-break: break-word; }
.muted { color: var(--muted); }
.evlist { margin: .25rem 0 .25rem 1rem; padding: 0; }
.evlist li { margin: .1rem 0; }
.primary-sig { font-weight: 600; }
td.copy { cursor: pointer; }
td.copy:hover { background: #8882; }
td.copy.copied { background: #16a34a55; }
details { margin: .25rem 0 1rem; }
summary { cursor: pointer; color: var(--muted); font-size: .9rem; padding: .25rem 0; }
tr.asum { cursor: pointer; }
/* The disclosure triangle is a real <button> so it is focusable and operable
   with Enter / Space; its click bubbles to the row toggle for mouse users. */
button.tri { appearance: none; -webkit-appearance: none; background: none; border: 0;
  display: inline-block; margin: 0 .5rem 0 0; padding: 0; cursor: pointer; color: #2563eb;
  font: inherit; font-size: 1rem; line-height: 1; vertical-align: middle;
  transition: transform .12s; }
button.tri:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; border-radius: 2px; }
tbody.actor.open tr.asum .tri { transform: rotate(90deg); }
@media (prefers-reduced-motion: reduce) { button.tri { transition: none; } }
/* Break the actor summary's UA onto its own line (like the per-client cid-ua),
   rather than letting it trail the IP/org and wrap only when the line fills. */
.actor-ua { display: block; color: var(--muted); font-size: .82rem; margin-top: 1px;
  word-break: break-word; }
tbody.actor .amem { display: none; }
tbody.actor.open .amem { display: table-row; }
tr.amem td.cid { padding-left: 1.6rem; }
tr.amem .cid-as { color: var(--muted); font-size: .82rem; }
/* Search box and active-network pill pinned together so jumping to a kind keeps
   the filter (and its clear control) in view. Opaque base so rows scroll under it. */
.filterbar { position: sticky; top: 0; z-index: 2; background: Canvas;
  padding: .5rem 0; margin: .5rem 0; border-bottom: 1px solid #8883; }
/* The kind's heading + blurb stay pinned at the top while the reader scrolls that
   kind's client list, so which kind (and its caveat) they're reading is always
   visible. It sticks within its own <section>, so it scrolls off as the next kind
   arrives -- the pinned header always names the kind currently in view. `top`
   tracks the filter bar's live height (published as --filterbar-h by the script,
   since it grows when filter pills appear) so the two never overlap; the opaque
   base hides rows scrolling underneath. The inter-section gap moves from the h2's
   top margin to the section itself -- inside the sticky box it would show as dead
   space above the heading once pinned. */
section.kind { margin-top: 2.25rem; }
.kindhead { position: sticky; top: var(--filterbar-h, 0px); z-index: 1;
  background: Canvas; padding-bottom: .3rem; }
/* scroll-margin-top: jumping to a kind aligns its top with the viewport top, but
   the sticky filter bar sits there -- so leave room for it (plus a little breathing
   space) and the heading lands just below the bar, not behind it. The id is on this
   h2, so the offset has to live here: on the section it doesn't apply to the element
   the jump actually targets, and the heading + first rows land behind the bar. */
.kindhead h2 { margin-top: 0;
  scroll-margin-top: calc(var(--filterbar-h, 0px) + 0.75rem); }
.kindhead .blurb { margin-bottom: 0; }
input.filter { display: block; width: 100%; max-width: 30rem; margin: 0;
  padding: .4rem .55rem; border: 1px solid #8886; border-radius: 6px;
  background: Canvas; color: CanvasText; font: inherit; }
footer { margin-top: 3rem; color: var(--muted); font-size: .85rem; }
""".strip()

# Click a client cell to copy its id (the value for `inspect --client`).
# Uses the async clipboard API where available, with an execCommand fallback
# that works on file:// pages where the API is blocked.
SCRIPT = """
document.addEventListener('click', function (event) {
  var cell = event.target.closest('[data-copy]');
  if (!cell) return;
  var text = cell.getAttribute('data-copy');
  var flash = function () {
    cell.classList.add('copied');
    setTimeout(function () { cell.classList.remove('copied'); }, 900);
  };
  function fallback() {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta); flash();
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flash, fallback);
  } else {
    fallback();
  }
}, false);

document.addEventListener('click', function (event) {
  if (event.target.closest('[data-copy]')) return;  // a copy cell, not a toggle
  var row = event.target.closest('tr.asum');
  if (!row) return;
  var body = row.parentNode;
  if (!body || !body.classList.contains('actor')) return;
  var open = body.classList.toggle('open');
  var tri = row.querySelector('.tri');
  if (tri) tri.setAttribute('aria-expanded', open ? 'true' : 'false');
}, false);

// Left arrow collapses every open "Show more" disclosure -- a quick way back to
// the folded view without hunting down each one. Skipped while the reader is
// typing (an input/textarea/select/contenteditable) or operating a focused
// scrollable table track -- both already answer to ArrowLeft themselves (text
// cursor / phone column picker / horizontal scroll), so hijacking it there
// would fight the reader's own keystroke instead of adding a shortcut.
document.addEventListener('keydown', function (event) {
  if (event.key !== 'ArrowLeft') return;
  if (event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
  var target = event.target;
  var tag = target && target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' ||
      (target && target.isContentEditable)) return;
  if (target && target.closest && target.closest('.tscroll')) return;
  var open = document.querySelectorAll('details[open]');
  for (var i = 0; i < open.length; i++) open[i].open = false;
}, false);

document.addEventListener('click', function (event) {
  // Opening an exclusive accordion (shared name=) closes whichever one was open,
  // possibly above the click -- the page collapses and the reader loses their
  // place. Pin the clicked summary: note its viewport offset, then correct the
  // scroll once the DOM has settled so it stays put.
  var summary = event.target.closest('summary');
  if (!summary) return;
  var details = summary.parentElement;
  if (!details || !details.hasAttribute('name') || details.open) return;
  var before = summary.getBoundingClientRect().top;
  requestAnimationFrame(function () {
    window.scrollBy(0, summary.getBoundingClientRect().top - before);
  });
}, false);

// The client list answers to three filters at once: the text box, a kind picked
// by clicking a table (which isolates that kind and hides the rest), and a network
// column from the cross-tab. activeKind is a kind value (matching section
// data-kind); activeNet is a column-index string (matching the cross-tab cells'
// data-net / the rows' data-netcol). A "Show all" control clears everything.
var activeKind = null, activeNet = null;

function netName(idx) {
  var th = document.querySelector('#nettab th[data-net="' + idx + '"]');
  if (!th) return 'network ' + idx;
  var span = th.querySelector('span');
  return (span ? span.textContent : th.textContent).trim();
}
function kindName(kind) {
  var badge = document.querySelector('#' + CSS.escape(kind) + ' .badge');
  return badge ? badge.textContent.trim() : kind;
}
function rowInNet(row, idx) {
  var attr = row.getAttribute('data-netcol');
  return !!attr && (' ' + attr + ' ').indexOf(' ' + idx + ' ') !== -1;
}
function setChip(id, label, value) {
  var chip = document.getElementById(id);
  if (!chip) return;
  if (value !== null) {
    chip.textContent = label + ': ' + value + '  \\u00d7';
    chip.hidden = false;
  } else {
    chip.textContent = '';
    chip.hidden = true;
  }
}

function applyFilters() {
  var input = document.querySelector('input.filter');
  var query = input ? input.value.trim().toLowerCase() : '';
  var on = query.length > 0 || activeNet !== null || activeKind !== null;
  // While filtering, force every "Show more" disclosure open so hidden matches
  // surface, and suspend the exclusive-accordion name= so all stay open at once;
  // restore both (name re-applied, disclosures re-collapsed) when cleared.
  var details = document.querySelectorAll('details');
  for (var d = 0; d < details.length; d++) {
    var det = details[d], from = on ? 'name' : 'data-name', to = on ? 'data-name' : 'name';
    if (det.hasAttribute(from)) { det.setAttribute(to, det.getAttribute(from)); det.removeAttribute(from); }
    det.open = on;
  }
  // Toggle every client row across every kind against the text query AND the network.
  var rows = document.querySelectorAll('tr.frow');
  for (var i = 0; i < rows.length; i++) {
    var hay = rows[i].getAttribute('data-filter') || '';
    var textok = query === '' || hay.indexOf(query) !== -1;
    var netok = activeNet === null || rowInNet(rows[i], activeNet);
    rows[i].style.display = (textok && netok) ? '' : 'none';
  }
  // Kind isolation: when a kind is picked, hide every other kind section outright.
  // Otherwise (and within the shown kind) collapse a section or an emptied "Show
  // more" disclosure when no client row in it survives the row filters.
  var sections = document.querySelectorAll('section.kind');
  for (var s = 0; s < sections.length; s++) {
    var sec = sections[s];
    if (activeKind !== null && sec.getAttribute('data-kind') !== activeKind) {
      sec.style.display = 'none'; continue;
    }
    var liveS = sec.querySelectorAll('tr.frow:not([style*="none"])');
    sec.style.display = (!on || liveS.length) ? '' : 'none';
  }
  for (var e = 0; e < details.length; e++) {
    var liveD = details[e].querySelectorAll('tr.frow:not([style*="none"])');
    details[e].style.display = (!on || liveD.length) ? '' : 'none';
  }
  // When the filters hide every client, say so -- otherwise the client area just
  // collapses to nothing and the reader can't tell a narrow query from a bug.
  var msg = document.getElementById('nomatch');
  if (msg) {
    if (on && !document.querySelector('section.kind:not([style*="none"]) tr.frow:not([style*="none"])')) {
      var bits = [];
      if (activeKind !== null) bits.push(kindName(activeKind) + ' clients');
      else bits.push('clients');
      if (query) bits.push('matching \\u201c' + (input ? input.value.trim() : '') + '\\u201d');
      if (activeNet !== null) bits.push('on the ' + netName(activeNet) + ' network');
      msg.textContent = 'No ' + bits.join(' ') + '.';
      msg.hidden = false;
    } else {
      msg.hidden = true;
    }
  }
  // Pills reflect the active kind / network; the "Show all" control appears
  // whenever any filter is on.
  setChip('kindfilter', 'Kind', activeKind === null ? null : kindName(activeKind));
  setChip('netfilter', 'Network', activeNet === null ? null : netName(activeNet));
  var clear = document.getElementById('clearfilters');
  if (clear) clear.hidden = !on;
  markScrollables();  // hiding rows can change a table's width and overflow
  syncFilterbarHeight();  // showing/hiding pills changes the bar's height
  syncHash(input ? input.value.trim() : '');
}

// Set while the page-load restore below is applying a fragment it just read,
// so syncHash doesn't immediately rewrite that fragment (e.g. a shared
// old-style #kind-id link would otherwise flip to #kind=id before the reader
// does anything).
var restoringFromHash = false;

// Mirror the active filters into the URL fragment so the report can be linked
// with a filter already applied. replaceState (not location.hash=) so this
// doesn't spam browser history or trigger a scroll-to-fragment jump on every
// keystroke.
function syncHash(query) {
  if (restoringFromHash) return;
  var params = new URLSearchParams();
  if (query) params.set('q', query);
  if (activeKind !== null) params.set('kind', activeKind);
  if (activeNet !== null) params.set('net', activeNet);
  var str = params.toString();
  var url = location.pathname + location.search + (str ? '#' + str : '');
  history.replaceState(null, '', url);
}

// Read the fragment back into filter state. A bare fragment with no "=" is
// treated as a kind id, for back-compat with plain #kind-id anchors (e.g. a
// link opened in a new tab, which bypasses the in-page anchor handler below)
// -- but only when it actually names a kind section, so an unrelated page id
// (a control's id, a table id, ...) reached via a hand-typed or stale URL
// doesn't get misread as a kind filter.
function parseHash() {
  var h = location.hash.slice(1);
  if (!h) return { q: '', kind: null, net: null };
  if (h.indexOf('=') === -1) {
    var known = document.querySelector('section.kind[data-kind="' + CSS.escape(h) + '"]');
    return { q: '', kind: known ? h : null, net: null };
  }
  var params = new URLSearchParams(h);
  return { q: params.get('q') || '', kind: params.get('kind') || null, net: params.get('net') || null };
}

// Set / clear the table-driven filters. Pass null for a dimension to leave it
// cleared. Exposed on window so the table scripts stay decoupled from this one.
window.setKindNet = function (kind, net) {
  activeKind = (kind === null || kind === undefined || kind === '') ? null : String(kind);
  activeNet = (net === null || net === undefined || net === '') ? null : String(net);
  applyFilters();
};
// Back-compat: a network-only setter (leaves the kind filter as-is).
window.setNetFilter = function (idx) { window.setKindNet(activeKind, idx); };

// Smooth-scroll to a kind section (or the filter bar) once filtering has settled.
window.scrollToKind = function (kind) {
  var target = (kind && document.getElementById(kind)) || document.querySelector('.filterbar');
  if (target && target.scrollIntoView)
    requestAnimationFrame(function () { target.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
};

document.addEventListener('input', function (event) {
  if (event.target.classList && event.target.classList.contains('filter')) applyFilters();
}, false);

// A kind link in a non-cross-tab table (e.g. "Summary by kind") isolates that
// kind instead of just jumping to it. The cross-tab handles its own clicks.
document.addEventListener('click', function (event) {
  var a = event.target.closest('a[href^="#"]');
  if (!a || a.closest('#nettab')) return;
  var id = a.getAttribute('href').slice(1), sec = document.getElementById(id);
  if (sec && sec.closest && sec.closest('section.kind')) {
    event.preventDefault();
    window.setKindNet(id, null);
    window.scrollToKind(id);
  }
}, false);

// Clear a single dimension from its pill, or everything from "Show all"
// (click, or Enter / Space for keyboard).
function filterControl(target) {
  if (!target || !target.closest) return null;
  if (target.closest('#kindfilter')) return 'kind';
  if (target.closest('#netfilter')) return 'net';
  if (target.closest('#clearfilters')) return 'all';
  return null;
}
function runFilterControl(which) {
  if (which === 'kind') window.setKindNet(null, activeNet);
  else if (which === 'net') window.setKindNet(activeKind, null);
  else if (which === 'all') {
    var input = document.querySelector('input.filter');
    if (input) input.value = '';
    window.setKindNet(null, null);
    // Re-showing every section shifts the page under the reader; without this the
    // browser anchors them mid-document (at the first browser client). Go to the
    // top so "Show all" reliably means "back to the whole report from the start".
    requestAnimationFrame(function () { window.scrollTo({ top: 0, behavior: 'smooth' }); });
  }
}
document.addEventListener('click', function (event) {
  var which = filterControl(event.target);
  if (which) runFilterControl(which);
}, false);
document.addEventListener('keydown', function (event) {
  var which = filterControl(event.target);
  // Only the role="button" pills need synthetic activation; the native
  // <button id="clearfilters"> fires its own click on Enter/Space already.
  if ((which === 'kind' || which === 'net') &&
      (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar')) {
    event.preventDefault(); runFilterControl(which);
  }
}, false);

// Make a table's horizontal-scroll track keyboard-operable, but ONLY while it
// actually overflows -- a focusable region with nothing to scroll is a dead tab
// stop. Re-checked on resize and after filtering. The accessible name is taken
// from the nearest preceding heading so a screen reader says which table it is.
function markScrollables() {
  var wraps = document.querySelectorAll('.tscroll');
  for (var i = 0; i < wraps.length; i++) {
    var el = wraps[i], over = el.scrollWidth - el.clientWidth > 1;
    if (over && el.tabIndex < 0) {
      el.tabIndex = 0;
      el.setAttribute('role', 'region');
      el.setAttribute('aria-label', scrollLabel(el) + ' (scrollable)');
    } else if (!over && el.hasAttribute('role')) {
      el.removeAttribute('tabindex');
      el.removeAttribute('role');
      el.removeAttribute('aria-label');
    }
  }
}
function scrollLabel(el) {
  for (var n = el; n && n.tagName !== 'BODY'; n = n.parentElement) {
    for (var p = n.previousElementSibling; p; p = p.previousElementSibling) {
      if (/^H[1-3]$/.test(p.tagName)) return p.textContent.trim().replace(/\\s+/g, ' ');
      var h = p.querySelector && p.querySelector('h1,h2,h3');
      if (h) return h.textContent.trim().replace(/\\s+/g, ' ');
    }
  }
  return 'Table';
}
// Publish the filter bar's current height so the sticky kind headers can pin just
// below it (top: var(--filterbar-h)). It grows when filter pills wrap, so this is
// re-run after every filter change and on resize, not just once.
function syncFilterbarHeight() {
  var bar = document.querySelector('.filterbar');
  if (bar) document.documentElement.style.setProperty('--filterbar-h', bar.offsetHeight + 'px');
}
syncFilterbarHeight();
markScrollables();

// Auto-apply whatever filter the URL fragment encodes, so a link with a filter
// baked in reproduces that view on load instead of showing the whole report.
(function () {
  var state = parseHash();
  if (!state.q && !state.kind && !state.net) return;
  var input = document.querySelector('input.filter');
  if (input && state.q) input.value = state.q;
  restoringFromHash = true;
  window.setKindNet(state.kind, state.net);  // normalizes '' to null, same as any other setter
  restoringFromHash = false;
  // Any fragment-encoded filter means the reader came for filtered results, not
  // the summary tables -- scroll past them (to the kind section, or to the
  // filterbar immediately below them when the filter is query/network-only).
  window.scrollToKind(state.kind);
})();

(function () {
  var t;
  window.addEventListener('resize', function () {
    clearTimeout(t);
    t = setTimeout(function () { markScrollables(); syncFilterbarHeight(); }, 150);
  }, false);
})();
""".strip()
