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
.netdiv { border-left: 2px solid #8887; }
th.netoff { background: #8881; }
tr.netall td { border-top: 2px solid #8887; }
.netctl { font-size: .9rem; color: var(--muted); margin: .25rem 0 .6rem; }
.netctl select { font: inherit; margin-left: .35rem; }
/* On a phone the cross-tab can't show every network column at readable width, so
   it folds to Kind | one chosen network | Total and the picker swaps the column
   in place (same idea as the desktop "break out" control). Desktop shows all. */
.netcolctl, .netnarrow { display: none; }
@media (max-width: 640px) {
  .netcolctl { display: inline; }
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
  border-radius: 6px; background: #8883; font-size: .78rem; white-space: nowrap; cursor: help; }
.flag { cursor: help; font-style: normal; }
.blurb { color: var(--muted); margin: .15rem 0 .6rem; }
.bar { background: #8883; border-radius: 4px; height: .7rem; min-width: 2px; }
.card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem;
  word-break: break-all; }
td.cid { max-width: 26rem; }
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
.actor-ua { color: var(--muted); font-size: .82rem; margin-left: .5rem; }
tbody.actor .amem { display: none; }
tbody.actor.open .amem { display: table-row; }
tr.amem td.cid { padding-left: 1.6rem; }
tr.amem .cid-as { color: var(--muted); font-size: .82rem; }
input.filter { display: block; width: 100%; max-width: 30rem; margin: .5rem 0;
  padding: .4rem .55rem; border: 1px solid #8886; border-radius: 6px;
  background: Canvas; color: CanvasText; font: inherit;
  position: sticky; top: .5rem; z-index: 1; }
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

document.addEventListener('input', function (event) {
  var input = event.target;
  if (!input.classList || !input.classList.contains('filter')) return;
  var query = input.value.trim().toLowerCase();
  var on = query.length > 0;
  // While filtering, force every "Show more" disclosure open so hidden matches
  // surface, and suspend the exclusive-accordion name= so all stay open at once;
  // restore both (name re-applied, disclosures re-collapsed) when cleared.
  var details = document.querySelectorAll('details');
  for (var d = 0; d < details.length; d++) {
    var det = details[d], from = on ? 'name' : 'data-name', to = on ? 'data-name' : 'name';
    if (det.hasAttribute(from)) { det.setAttribute(to, det.getAttribute(from)); det.removeAttribute(from); }
    det.open = on;
  }
  // Toggle every client row across every kind against the one query.
  var rows = document.querySelectorAll('tr.frow');
  for (var i = 0; i < rows.length; i++) {
    var hay = rows[i].getAttribute('data-filter') || '';
    rows[i].style.display = hay.indexOf(query) === -1 ? 'none' : '';
  }
  // Collapse a section (header and all) or an emptied disclosure when no client
  // row in it survives the filter; restore when cleared.
  var boxes = document.querySelectorAll('section.kind, details');
  for (var b = 0; b < boxes.length; b++) {
    var live = boxes[b].querySelectorAll('tr.frow:not([style*="none"])');
    boxes[b].style.display = (!on || live.length) ? '' : 'none';
  }
  markScrollables();  // hiding rows can change a table's width and overflow
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
markScrollables();
(function () {
  var t;
  window.addEventListener('resize', function () {
    clearTimeout(t);
    t = setTimeout(markScrollables, 150);
  }, false);
})();
""".strip()
