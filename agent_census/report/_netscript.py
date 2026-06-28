"""Client-side script for the "Requests by kind and network" table.

Three jobs: the counts/% toggle (``#netmode``) that repaints the heat map down
columns or across rows; pinning the Kind column (left) and the Other / off-network
/ Total columns (right) while the named-datacentre columns scroll between them; and
keeping the pinned "Other datacenters" column live -- it tallies the folded tail
plus whatever datacentre columns are still scrolled off to the right (not yet
revealed), with a ``+N`` header cue. On a phone the table folds to one column
instead (see the media query),
so the pinning and live tally switch off there.
"""

from __future__ import annotations

NET_SCRIPT = """
<script>
(function(){
  var tab=document.getElementById('nettab'); if(!tab) return;
  var track=tab.parentNode;
  var sel=document.getElementById('netmode');
  var cells=[].slice.call(tab.querySelectorAll('td.mxcell'));
  var byRow={}, byCol={};
  cells.forEach(function(c){
    var r=c.parentNode.rowIndex, col=c.cellIndex; c._v=+c.getAttribute('data-v');
    c._other=c.classList.contains('othercol');  // live aggregate: keep it out of the scale
    (byRow[r]=byRow[r]||[]).push(c);
    (byCol[col]=byCol[col]||[]).push(c);
  });
  function red(a){ return 'linear-gradient(rgba(220,38,38,'+a+'),rgba(220,38,38,'+a+'))'; }
  // Heat is a background-IMAGE layer over each cell's opaque base, so a pinned cell
  // stays solid above the columns scrolling behind it.
  function paint(mode){
    var groups=(mode==='col')?byCol:byRow;
    cells.forEach(function(c){c.style.backgroundImage='';c.style.fontWeight='';});
    Object.keys(groups).forEach(function(k){
      var g=groups[k], tot=0, mx=0, any=false;
      // Scale to the static cells only. The live "Other" cell's value moves as you
      // scroll (it folds in hidden columns); letting it set mx/tot would re-shade
      // every named column on every frame -- the blue "shift". Its own column (col
      // mode) is all-Other, so fall back to scaling it among itself.
      g.forEach(function(c){if(!c._other){any=true; tot+=c._v; if(c._v>mx)mx=c._v;}});
      if(!any) g.forEach(function(c){tot+=c._v; if(c._v>mx)mx=c._v;});
      g.forEach(function(c){
        var v=c._v;
        c.textContent=(mode==='count')?(v?v.toLocaleString():'\\u2013')
                                       :((v&&tot)?Math.round(v/tot*100)+'%':'\\u2013');
        if(v>0&&mx>0){var a=(Math.min(v/mx,1)*0.8).toFixed(3);
          c.style.backgroundImage='linear-gradient(rgb(var(--heat) / '+a+'),rgb(var(--heat) / '+a+'))';}
        if(v>0&&v===mx) c.style.fontWeight='500';
      });
    });
  }

  // --- pinned-column geometry: set each right-pinned column's offset, measure the
  //     left/right frozen widths used to decide which datacentre columns are hidden.
  var headRow=tab.rows[0];
  var stickR=[].slice.call(headRow.cells).filter(function(c){return c.classList.contains('stick-r');});
  var rightW=0;
  function isPhone(){ return window.matchMedia && window.matchMedia('(max-width: 640px)').matches; }
  function layout(){
    if(isPhone()){ rightW=0; return; }
    var acc=0;
    for(var i=stickR.length-1;i>=0;i--){
      var ci=stickR[i].cellIndex, off=Math.ceil(acc);  // ceil so pinned columns overlap, not gap
      for(var r=0;r<tab.rows.length;r++){var cell=tab.rows[r].cells[ci]; if(cell) cell.style.right=off+'px';}
      acc+=stickR[i].getBoundingClientRect().width;
    }
    rightW=Math.ceil(acc);
  }

  // --- live "Other datacenters": fold in datacentre columns scrolled off to the right.
  var otherCells=[].slice.call(tab.querySelectorAll('td.othercol'));
  var otherTot=tab.querySelector('td.othertot');
  var cue=tab.querySelector('.othercue');
  var dcsHd=[].slice.call(tab.querySelectorAll('th.dcs'));
  function rowSum(row, base, hidden){
    var s=base; for(var k in hidden){var c=row.cells[k]; if(c) s+=(+c.getAttribute('data-v')||0);} return s;
  }
  function recomputeOther(){
    if(!otherCells.length) return;
    if(isPhone()){  // folded view: Other is just its static tail
      otherCells.forEach(function(oc){oc._v=+oc.getAttribute('data-agg');});
      if(otherTot) otherTot.textContent=(+otherTot.getAttribute('data-agg')).toLocaleString();
      if(cue) cue.textContent='';
      paint(sel?sel.value:'count'); return;
    }
    // Only fold datacentre columns scrolled off to the RIGHT (still hidden behind
    // the pinned Other column -- not yet revealed). Columns scrolled past to the
    // left, under Kind, have already been read; re-adding them to Other just
    // double-counts what the reader already accounted for.
    var bandR=track.getBoundingClientRect().right-rightW;
    var hidden={}, n=0;
    dcsHd.forEach(function(th){
      var r=th.getBoundingClientRect();
      if(r.width && r.left>=bandR-0.5){ hidden[th.cellIndex]=1; n++; }
    });
    otherCells.forEach(function(oc){ oc._v=rowSum(oc.parentNode, +oc.getAttribute('data-agg'), hidden); });
    if(otherTot){
      var t=rowSum(otherTot.parentNode, +otherTot.getAttribute('data-agg'), hidden);
      otherTot.textContent=t.toLocaleString();
      var peak=+otherTot.getAttribute('data-peak')||0;
      otherTot.style.backgroundImage=(peak>0&&t>0)?red((Math.min(t/peak,1)*0.8).toFixed(3)):'';
    }
    if(cue) cue.textContent=n?('+'+n):'';
    paint(sel?sel.value:'count');
  }

  // One rAF-throttled frame for both scroll and resize; a pending resize forces a
  // re-measure even if a scroll frame got queued first (offsets would go stale).
  var raf=0, needLayout=false;
  function schedule(){ if(raf) return; raf=requestAnimationFrame(function(){
    raf=0; if(needLayout){ needLayout=false; layout(); } recomputeOther();
  }); }
  track.addEventListener('scroll', schedule, {passive:true});
  window.addEventListener('resize', function(){ needLayout=true; schedule(); });

  // Phone column picker: show only the chosen network column (CSS hides the rest
  // below the breakpoint; on desktop every column shows and this is a no-op).
  var colsel=document.getElementById('netcol');
  if(colsel){
    var colcells=[].slice.call(tab.querySelectorAll('[data-net]'));
    function showcol(idx){ colcells.forEach(function(c){c.classList.toggle('colshow',c.getAttribute('data-net')===idx);}); }
    colsel.addEventListener('change',function(){showcol(colsel.value);});
    showcol(colsel.value);
  }
  if(sel) sel.addEventListener('change',function(){paint(sel.value);});

  // Click any number to jump to its kind and filter the client list by its network.
  // The Kind cell keeps its own anchor (skip it). A network cell carries data-net
  // (its column index) -> filter that column; a Total-column number has none ->
  // clear the network filter. A kind row links to its section; the All-kinds row
  // has no link, so it jumps to the client filter box (the top of the kind list).
  tab.addEventListener('click',function(ev){
    var cell=ev.target.closest('td');
    if(!cell||cell.classList.contains('stick-l')) return;
    if(window.setNetFilter) window.setNetFilter(cell.getAttribute('data-net'));
    var link=cell.parentNode.querySelector('a[href^="#"]');
    var target=link?document.querySelector(link.getAttribute('href')):document.querySelector('input.filter');
    if(target&&target.scrollIntoView)
      requestAnimationFrame(function(){target.scrollIntoView({behavior:'smooth',block:'start'});});
  });

  layout(); paint('count'); recomputeOther();
  requestAnimationFrame(function(){ layout(); recomputeOther(); });  // re-measure once laid out
})();
</script>
""".strip()
