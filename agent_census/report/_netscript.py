"""Client-side script for the "Requests by kind and network" table.

Drives two controls: the counts/% toggle (``#netmode``) that repaints the heat
map down columns or across rows, and the break-out selector (``#netbreakout``)
that swaps the aggregated "Other datacenters" column for a single folded-in
provider's per-kind numbers.
"""

from __future__ import annotations

NET_SCRIPT = """
<script>
(function(){
  var tab=document.getElementById('nettab'); if(!tab) return;
  var sel=document.getElementById('netmode'); if(!sel) return;
  var cells=[].slice.call(tab.querySelectorAll('td.mxcell'));
  var byRow={}, byCol={};
  cells.forEach(function(c){
    var r=c.parentNode.rowIndex, col=c.cellIndex; c._v=+c.getAttribute('data-v');
    (byRow[r]=byRow[r]||[]).push(c);
    (byCol[col]=byCol[col]||[]).push(c);
  });
  function paint(mode){
    var groups=(mode==='col')?byCol:byRow;
    cells.forEach(function(c){c.style.background='';c.style.fontWeight='';});
    Object.keys(groups).forEach(function(k){
      var g=groups[k], tot=0, mx=0;
      g.forEach(function(c){tot+=c._v; if(c._v>mx)mx=c._v;});
      g.forEach(function(c){
        var v=c._v;
        c.textContent = (mode==='count') ? (v?v.toLocaleString():'\\u2013')
                                         : ((v&&tot)?Math.round(v/tot*100)+'%':'\\u2013');
        if(v>0&&mx>0) c.style.background='rgb(var(--heat) / '+(v/mx*0.8).toFixed(3)+')';
        if(v>0&&v===mx) c.style.fontWeight='500';
      });
    });
  }
  var bsel=document.getElementById('netbreakout');
  var bdataEl=document.getElementById('netbreakdata');
  if(bsel&&bdataEl){
    var bdata=JSON.parse(bdataEl.textContent);
    var others=[].slice.call(tab.querySelectorAll('td.othercol'));
    var otot=tab.querySelector('td.othertot');
    var ohd=document.getElementById('netotherhd');
    var oname=ohd?ohd.textContent:'';
    bsel.addEventListener('change',function(){
      var name=bsel.value, m=name?bdata[name]:null, sum=0;
      others.forEach(function(c){
        var v=name?(m[c.getAttribute('data-kind')]||0):(+c.getAttribute('data-agg'));
        c._v=v; sum+=v;
      });
      if(otot){var tv=name?sum:(+otot.getAttribute('data-agg'));otot.textContent=tv.toLocaleString();}
      if(ohd) ohd.textContent=name||oname;
      paint(sel.value);
    });
  }
  // Phone column picker: show only the chosen network column (CSS hides the rest
  // below the breakpoint; on desktop every column shows and this is a no-op).
  var colsel=document.getElementById('netcol');
  if(colsel){
    var colcells=[].slice.call(tab.querySelectorAll('[data-net]'));
    function showcol(idx){
      colcells.forEach(function(c){c.classList.toggle('colshow',c.getAttribute('data-net')===idx);});
    }
    colsel.addEventListener('change',function(){showcol(colsel.value);});
    showcol(colsel.value);
  }
  sel.addEventListener('change',function(){paint(sel.value);});
  paint('count');
})();
</script>
""".strip()
