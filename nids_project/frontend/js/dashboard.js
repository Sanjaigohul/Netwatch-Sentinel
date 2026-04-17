'use strict';
/* ═══════════════════════════════════════════════════════════
   NIDS Sentinel – dashboard.js
   ═══════════════════════════════════════════════════════════ */

// ── State ──────────────────────────────────────────────────────────────────
const _alertStore = [];  // indexed alert storage for AI analysis
const S = {
  page: 'dashboard', sound: true,
  monPaused: false, monFilter: 'all', monRows: [], MAX_MON: 200,
  alerts: [], logsPage: 1, logTimer: null,
  datasets: [], trainPolling: null,
  stats: {}, alertCounts: {Critical:0, High:0, Medium:0, Low:0},
  ppsHistory: new Array(60).fill(0),
};

// ── Page navigation ────────────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard:'Dashboard', monitor:'Live Monitor', alerts:'Alerts',
  logs:'Log Table', network:'IP Manager', simulate:'Simulate',
  train:'Train Models', settings:'Settings',
};
function goPage(p) {
  document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const pg = document.getElementById(`page-${p}`);
  if (pg) pg.classList.add('active');
  const nav = document.querySelector(`[data-page="${p}"]`);
  if (nav) nav.classList.add('active');
  document.getElementById('pageTitle').textContent = PAGE_TITLES[p] || p;
  S.page = p;
  if (p==='logs')    loadLogs();
  if (p==='alerts')  loadAlerts();
  if (p==='network') loadLists();
  if (p==='train')   checkTrainStatus();
}
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('hidden');
}

// ── Charts ─────────────────────────────────────────────────────────────────
Chart.defaults.color = '#94a3b8';

const trafficChart = new Chart(
  document.getElementById('trafficChart').getContext('2d'), {
  type: 'line',
  data: {
    labels: Array.from({length:60},(_,i)=>`-${60-i}s`),
    datasets: [{
      label: 'pps', data: S.ppsHistory,
      borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,.06)',
      borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0,
    },{
      label: 'anomalies', data: new Array(60).fill(0),
      borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,.05)',
      borderWidth: 1.5, fill: true, tension: 0.4, pointRadius: 0,
    }],
  },
  options: {
    responsive:true, maintainAspectRatio:false, animation:{duration:0},
    scales:{
      x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{maxTicksLimit:8,font:{size:10}}},
      y:{grid:{color:'rgba(255,255,255,.04)'},beginAtZero:true,ticks:{font:{size:10}}},
    },
    plugins:{legend:{display:false}},
  },
});

const pieChart = new Chart(
  document.getElementById('pieChart').getContext('2d'), {
  type: 'doughnut',
  data: {labels:['No data'],datasets:[{data:[1],backgroundColor:['rgba(255,255,255,.05)'],borderWidth:0}]},
  options: {
    responsive:true, maintainAspectRatio:false, animation:{duration:400},
    cutout:'65%',
    plugins:{legend:{position:'right',labels:{font:{size:10},padding:8,boxWidth:10}}},
  },
});

const simChart = new Chart(
  document.getElementById('simChart').getContext('2d'), {
  type: 'bar',
  data: {
    labels: ['Normal','DoS','DDoS','Scan','Brute','Botnet','Web'],
    datasets: [{
      data: [0,0,0,0,0,0,0],
      backgroundColor: ['#10b981','#ef4444','#dc2626','#f59e0b','#8b5cf6','#f97316','#ec4899'],
      borderRadius: 4,
    }],
  },
  options: {
    responsive:true, maintainAspectRatio:false, animation:{duration:300},
    scales:{
      x:{grid:{display:false},ticks:{font:{size:9}}},
      y:{grid:{color:'rgba(255,255,255,.04)'},beginAtZero:true,ticks:{font:{size:9}}},
    },
    plugins:{legend:{display:false}},
  },
});

// Attack type colours
const ATK_COLORS = {
  Normal:'#10b981',DoS:'#ef4444',DDoS:'#dc2626',
  PortScan:'#f59e0b',BruteForce:'#8b5cf6',Botnet:'#f97316',WebAttack:'#ec4899',
};

function updatePie(dist) {
  const entries = Object.entries(dist||{}).filter(([k])=>k!=='Normal');
  if (!entries.length) return;
  pieChart.data.labels   = entries.map(([k])=>k);
  pieChart.data.datasets[0].data = entries.map(([,v])=>v);
  pieChart.data.datasets[0].backgroundColor = entries.map(([k])=>ATK_COLORS[k]||'#94a3b8');
  pieChart.update();
}
function updateTraffic(hist) {
  if (!hist||!hist.length) return;
  const d = hist.slice(-60);
  trafficChart.data.datasets[0].data = d;
  trafficChart.update();
  const last = d[d.length-1]||0;
  document.getElementById('ppsLabel').textContent = `${last} pps`;
  document.getElementById('topPps').textContent   = `${last} pps`;
  document.getElementById('kpiPps').textContent   = `${last} pkt/s`;
}
function updateSimChart(dist) {
  const labels = ['Normal','DoS','DDoS','PortScan','BruteForce','Botnet','WebAttack'];
  simChart.data.datasets[0].data = labels.map(l=>dist[l]||0);
  simChart.update();
}

// ── Stats rendering ────────────────────────────────────────────────────────
function renderStats(s) {
  S.stats = s;
  const total = s.total_packets||0, anoms = s.anomalies||0;
  setText('kpiTotal',    fmtN(total));
  setText('kpiAnomaly',  fmtN(anoms));
  setText('kpiThreats',  fmtN(s.active_threats||0));
  setText('kpiNormal',   fmtN((total-anoms)||0));
  setText('kpiAnomalyPct', `${((anoms/Math.max(total,1))*100).toFixed(1)}%`);
  setText('kpiNormalPct',  `${(((total-anoms)/Math.max(total,1))*100).toFixed(1)}%`);
  // Threat level
  const dist  = s.attack_distribution||{};
  const tl    = getOverallThreat(dist);
  const tlEl  = document.getElementById('kpiThreatLvl');
  tlEl.textContent = tl;
  tlEl.style.color = {Low:'#10b981',Medium:'#f59e0b',High:'#ef4444',Critical:'#dc2626'}[tl]||'#94a3b8';
  const top = Object.entries(dist).sort((a,b)=>b[1]-a[1])[0];
  setText('kpiTopAtk', top?`Top: ${top[0]}`:'—');
  // Charts
  updateTraffic(s.pps_history);
  updatePie(dist);
  updateSimChart(dist);
  renderTopAttackers(s.top_attackers||[]);
  // Sidebar badges
  const badge = document.getElementById('badge-monitor');
  if (badge) badge.textContent = fmtN(total);
  // System status
  const dot  = document.getElementById('sysStatusDot');
  const txt  = document.getElementById('sysStatusText');
  if (anoms > 0 || (s.active_threats||0) > 0) {
    dot.className = 'status-dot alert';
    txt.textContent = `⚠ ALERT (${s.active_threats||0})`;
  } else {
    dot.className = 'status-dot active';
    txt.textContent = 'ACTIVE';
  }
  // Settings info
  setText('infoMode',   s.simulation_mode ? 'Simulation' : 'Live Capture');
  setText('infoIfw',    `${((s.if_weight||0.5)*100).toFixed(0)}%`);
  setText('infoLstmw',  `${((1-(s.if_weight||0.5))*100).toFixed(0)}%`);
  setText('infoThresh', (s.threshold||0).toFixed(3));
  const dbEl = document.getElementById('infoDB');
  if (dbEl) {
    if (s.db_available) {
      dbEl.innerHTML = '✅ Connected';
      dbEl.style.color = 'var(--green)';
    } else {
      dbEl.innerHTML = '⚠ Not Connected <span style="font-size:.7rem;color:var(--text3)">– copy .env.example to .env</span>';
      dbEl.style.color = 'var(--yellow)';
    }
  }
}
function getOverallThreat(dist) {
  if (dist.DDoS||dist.Botnet) return 'Critical';
  if (dist.DoS||dist.BruteForce||dist.WebAttack) return 'High';
  if (dist.PortScan) return 'Medium';
  return 'Low';
}
function renderTopAttackers(list) {
  const el = document.getElementById('topAttackers');
  if (!list.length) { el.innerHTML='<div class="empty-msg">No attackers</div>'; return; }
  const max = list[0].count||1;
  el.innerHTML = list.map(a=>`
    <div class="atk-row">
      <span class="atk-ip">${a.ip}</span>
      <div class="atk-bar-bg"><div class="atk-bar-fill" style="width:${(a.count/max*100).toFixed(0)}%"></div></div>
      <span class="atk-count">${a.count}</span>
    </div>`).join('');
}

// ── Live Monitor ───────────────────────────────────────────────────────────
function addMonRow(e) {
  if (S.monPaused) return;
  if (S.monFilter==='anomaly' && e.final_result!=-1) return;
  if (S.monFilter==='normal'  && e.final_result==-1) return;
  S.monRows.unshift(e);
  if (S.monRows.length>S.MAX_MON) S.monRows.pop();
  const tbody = document.getElementById('monBody');
  const isAnom= e.final_result===-1;
  const tr = document.createElement('tr');
  if (isAnom) tr.className='anom';
  tr.innerHTML = `
    <td>${fmtT(e.timestamp)}</td>
    <td class="ip" title="${e.src_ip}">${e.src_ip}</td>
    <td title="${e.src_country||'—'}">${e.src_flag||'🌐'} ${e.src_country||'—'}</td>
    <td title="${e.src_isp||'—'}" style="max-width:120px;overflow:hidden;text-overflow:ellipsis">${e.src_isp||'—'}</td>
    <td class="ip">${e.dst_ip}</td>
    <td>${e.protocol}</td>
    <td>${fmtBytes(e.bytes||e.packet_length)}</td>
    <td>${e.duration||0}s</td>
    <td>${mlBadge(e.ml_result)}</td><td>${mlBadge(e.dl_result)}</td>
    <td>${resBadge(e.final_result)}</td>
    <td><span class="atk-${e.attack_type}">${e.attack_type}</span></td>
    <td><span class="badge threat-${e.threat_level}">${e.threat_level}</span></td>
    <td>${e.anomaly_score.toFixed(3)}</td>`;
  if (tbody.firstChild?.colSpan===11) tbody.innerHTML='';
  tbody.insertBefore(tr, tbody.firstChild);
  while(tbody.children.length>S.MAX_MON) tbody.removeChild(tbody.lastChild);
  const cnt = document.getElementById('monCount');
  if (cnt) cnt.textContent=`${S.monRows.length} packets`;
}
function toggleMonPause() {
  S.monPaused=!S.monPaused;
  const btn=document.getElementById('monPauseBtn');
  btn.textContent=S.monPaused?'▶ Resume':'⏸ Pause';
  btn.style.borderColor=S.monPaused?'var(--red)':'';
  btn.style.color=S.monPaused?'var(--red)':'';
}
function applyMonFilter() {
  S.monFilter=document.getElementById('monFilter').value;
  document.getElementById('monBody').innerHTML='<tr><td colspan="11" class="empty-cell">Filter applied — waiting for new packets</td></tr>';
  S.monRows=[];
}

// ── Alert feed ─────────────────────────────────────────────────────────────
function addAlert(a) {
  const isNormal = a.threat_level === 'Info' || a.final_result === 1;
  _alertStore.unshift(a);
  if (_alertStore.length>500) _alertStore.pop();
  S.alerts.unshift(a);
  if (S.alerts.length>500) S.alerts.pop();
  if (!isNormal) {
    S.alertCounts[a.threat_level]=(S.alertCounts[a.threat_level]||0)+1;
    playSound();
  }
  // Dashboard feed
  const feed=document.getElementById('dashAlerts');
  if (feed.querySelector('.empty-msg')) feed.innerHTML='';
  const el=document.createElement('div');
  if (isNormal && a.attack_type === 'Blocked') {
    // Blacklisted IP — show as info, not anomaly
    el.className='alert-card Info';
    el.innerHTML=`
      <span class="alert-icon">🚫</span>
      <div>
        <div class="alert-title"><span style="color:var(--yellow)">Blocked IP</span>
          <span class="badge" style="background:rgba(245,158,11,.15);color:#f59e0b;margin-left:.4rem">🚫 Blocked</span></div>
        <div class="alert-meta">${a.src_ip} → ${a.dst_ip} | ${a.protocol||'TCP'} | ${fmtT(a.timestamp)}</div>
      </div>`;
  } else if (isNormal) {
    el.className='alert-card Info';
    el.innerHTML=`
      <span class="alert-icon">🟢</span>
      <div>
        <div class="alert-title"><span style="color:var(--green)">Normal</span>
          <span class="badge" style="background:rgba(16,185,129,.15);color:#10b981;margin-left:.4rem">✓ OK</span></div>
        <div class="alert-meta">${a.src_ip} → ${a.dst_ip} | ${a.protocol||'TCP'} | ${fmtBytes(a.packet_length||0)} | ${fmtT(a.timestamp)}</div>
      </div>`;
  } else {
    el.className=`alert-card ${a.threat_level}`;
    el.innerHTML=`
      <span class="alert-icon">${alertIcon(a.threat_level)}</span>
      <div>
        <div class="alert-title"><span class="atk-${a.attack_type}">${a.attack_type}</span>
          <span class="badge threat-${a.threat_level}" style="margin-left:.4rem">${a.threat_level}</span></div>
        <div class="alert-meta">${a.src_ip} → ${a.dst_ip} | score:${a.anomaly_score} | ${fmtT(a.timestamp)}</div>
      </div>`;
  }
  feed.insertBefore(el, feed.firstChild);
  while(feed.children.length>60) feed.removeChild(feed.lastChild);
  // Badge (only count anomalies)
  const anomCount = S.alerts.filter(x => x.threat_level !== 'Info' && x.final_result !== 1).length;
  const badge=document.getElementById('badge-alerts');
  if(badge){badge.textContent=anomCount||'';badge.style.display=anomCount?'':'none';}
  // Toast for high severity only
  if(['High','Critical'].includes(a.threat_level)) toast(`🚨 ${a.attack_type} from ${a.src_ip}`,'danger',5000);
  // Sim log (only anomalies)
  if (!isNormal) appendSimLog(a);
}
function appendSimLog(a) {
  const el=document.getElementById('simLog');
  if(!el)return;
  const line=document.createElement('div');
  line.style.cssText='color:var(--red);padding:.1rem 0;border-bottom:1px solid var(--border)';
  line.textContent=`${fmtT(a.timestamp)} [${a.attack_type}] ${a.src_ip} score=${a.anomaly_score}`;
  el.insertBefore(line,el.firstChild);
  while(el.children.length>30) el.removeChild(el.lastChild);
}
function alertIcon(l){return {Low:'🟢',Medium:'🟡',High:'🔴',Critical:'💀'}[l]||'⚠️'}
function clearAlerts(){
  S.alerts=[]; S.alertCounts={Critical:0,High:0,Medium:0,Low:0};
  ['dashAlerts','alertList'].forEach(id=>{
    const el=document.getElementById(id);
    if(el)el.innerHTML='<div class="empty-msg">No alerts</div>';
  });
  setText('badge-alerts',''); updateAlertCounts();
}
function updateAlertCounts(){
  setText('aTotal',   S.alerts.length);
  setText('aCritical',S.alertCounts.Critical||0);
  setText('aHigh',    S.alertCounts.High||0);
  setText('aMedium',  S.alertCounts.Medium||0);
}
async function loadAlerts(){
  try{
    const r=await api('/api/alerts?limit=100');
    const data=await r.json();
    const attacks=data.filter(a=>a.final_result===-1 && a.threat_level!=='Info');
    S.alerts=attacks;
    S.alertCounts={Critical:0,High:0,Medium:0,Low:0};
    attacks.forEach(a=>S.alertCounts[a.threat_level]=(S.alertCounts[a.threat_level]||0)+1);
    const el=document.getElementById('alertList');
    if(!el)return;
    if(!attacks.length){el.innerHTML='<div class="empty-msg">No alerts</div>';updateAlertCounts();return;}
    _alertStore.length = 0; attacks.forEach(a => _alertStore.push(a));
    el.innerHTML=attacks.map((a,i)=>`
      <div class="alert-card ${a.threat_level}" style="margin:.4rem .5rem">
        <span class="alert-icon">${alertIcon(a.threat_level)}</span>
        <div style="flex:1">
          <div class="alert-title">
            <span class="atk-${a.attack_type}">${a.attack_type}</span>
            <span class="badge threat-${a.threat_level}" style="margin-left:.4rem">${a.threat_level}</span>
            <button onclick="analyzeAlert(${JSON.stringify(a).replace(/"/g,'&quot;')})" style="margin-left:.5rem;padding:.1rem .4rem;font-size:.65rem;border:1px solid var(--blue);background:none;color:var(--blue);border-radius:4px;cursor:pointer">🤖 AI</button>
          </div>
          <div class="alert-meta">${a.src_ip}${a.src_flag?' ('+a.src_flag+' '+a.src_country+')':''} → ${a.dst_ip} | ${fmtT(a.timestamp)}</div>
          ${a.src_isp ? '<div style="font-size:.68rem;color:var(--text3)">ISP: '+a.src_isp+'</div>' : ''}
        </div>
      </div>`).join('');
    updateAlertCounts();
  }catch(e){console.error(e)}
}

// ── Logs ────────────────────────────────────────────────────────────────────
async function loadLogs(){
  const search=document.getElementById('logSearch')?.value||'';
  const threat=document.getElementById('logThreat')?.value||'';
  const result=document.getElementById('logResult')?.value||'';
  const time  =document.getElementById('logTime')?.value||'';
  const p = new URLSearchParams({page:S.logsPage,limit:50,search,threat,result,time_range:time});
  try{
    const r=await api(`/api/logs?${p}`);
    const data=await r.json();
    const tbody=document.getElementById('logBody');
    if(!data.logs?.length){tbody.innerHTML='<tr><td colspan="10" class="empty-cell">No records</td></tr>';return;}
    tbody.innerHTML=data.logs.map(e=>`
      <tr class="${e.final_result===-1?'anom':''}">
        <td>${fmtT(e.timestamp)}</td>
        <td class="ip" title="${e.src_ip}">${e.src_ip}</td>
        <td title="${e.src_country||'—'}">${e.src_flag||'🌐'} ${e.src_country||'—'}</td>
        <td style="max-width:110px;overflow:hidden;text-overflow:ellipsis" title="${e.src_isp||'—'}">${e.src_isp||'—'}</td>
        <td class="ip">${e.dst_ip}</td>
        <td>${e.protocol}</td>
        <td>${fmtBytes(e.bytes||e.packet_length)}</td>
        <td>${mlBadge(e.ml_result)}</td><td>${mlBadge(e.dl_result)}</td>
        <td>${resBadge(e.final_result)}</td>
        <td><span class="atk-${e.attack_type}">${e.attack_type}</span></td>
        <td><span class="badge threat-${e.threat_level}">${e.threat_level}</span></td>
        <td>${(e.anomaly_score||0).toFixed(3)}</td>
      </tr>`).join('');
    renderPager(data.total, data.page, data.pages);
  }catch(e){console.error(e)}
}
function debounceLog(){clearTimeout(S.logTimer);S.logTimer=setTimeout(()=>{S.logsPage=1;loadLogs();},300)}
function searchLog(e){if(e&&e.key==='Enter'){clearTimeout(S.logTimer);S.logsPage=1;loadLogs();}else{debounceLog();}}
function renderPager(total, page, pages){
  const el=document.getElementById('logPager'); if(!el)return;
  let html=`<span class="pg-info">${total} records</span>`;
  html+=`<button class="pg-btn" ${page<=1?'disabled':''} onclick="goLog(${page-1})">◀</button>`;
  const s=Math.max(1,page-2), e2=Math.min(pages,page+2);
  for(let i=s;i<=e2;i++) html+=`<button class="pg-btn ${i===page?'active':''}" onclick="goLog(${i})">${i}</button>`;
  html+=`<button class="pg-btn" ${page>=pages?'disabled':''} onclick="goLog(${page+1})">▶</button>`;
  el.innerHTML=html;
}
function goLog(p){S.logsPage=p;loadLogs()}
function exportCSV(){window.location.href='/api/export-csv';toast('Downloading logs…','info')}

// ── IP Manager ──────────────────────────────────────────────────────────────
async function loadLists(){
  const [bl,wl]=await Promise.all([
    api('/api/blacklist').then(r=>r.json()).catch(()=>[]),
    api('/api/whitelist').then(r=>r.json()).catch(()=>[]),
  ]);
  renderIpList('blList', bl, 'blacklist');
  renderIpList('wlList', wl, 'whitelist');
}
function renderIpList(id, items, type){
  const el=document.getElementById(id); if(!el)return;
  if(!items.length){el.innerHTML='<li class="empty-msg">Empty</li>';return;}
  el.innerHTML=items.map(it=>`
    <li>
      <span class="ip-addr">${it.ip_address}</span>
      <span class="ip-reason">${it.reason||''}</span>
      <button class="del-btn" onclick="removeIp('${type}','${it.ip_address}')">✕</button>
    </li>`).join('');
}
async function addBlacklist(){
  const ip=document.getElementById('blIp').value.trim();
  const reason=document.getElementById('blReason').value.trim();
  if(!ip){toast('Enter an IP','warning');return;}
  await api('/api/blacklist','POST',{ip,reason});
  document.getElementById('blIp').value='';
  document.getElementById('blReason').value='';
  toast(`${ip} blocked`,'danger'); loadLists();
}
async function addWhitelist(){
  const ip=document.getElementById('wlIp').value.trim();
  const reason=document.getElementById('wlReason').value.trim();
  if(!ip){toast('Enter an IP','warning');return;}
  await api('/api/whitelist','POST',{ip,reason});
  document.getElementById('wlIp').value='';
  document.getElementById('wlReason').value='';
  toast(`${ip} trusted`,'success'); loadLists();
}
async function removeIp(type,ip){
  await api(`/api/${type}/${ip}`,'DELETE');
  toast(`${ip} removed`,'info'); loadLists();
}

// ── Simulate ────────────────────────────────────────────────────────────────
async function simulate(type){
  await api('/api/simulate','POST',{type});
  const name=type||'Random';
  document.getElementById('simStatus').textContent=`▶ Injecting: ${name} attack…`;
  document.getElementById('simStatus').style.color='var(--red)';
  toast(`🚀 ${name} attack injected`,'danger',4000);
}
async function stopSim(){
  await api('/api/simulate/stop','POST');
  document.getElementById('simStatus').textContent='⏹ Attack stopped';
  document.getElementById('simStatus').style.color='var(--green)';
  toast('Attack stopped','success');
}

// ── Thresholds ──────────────────────────────────────────────────────────────
async function applyThresholds(){
  const hybrid=parseFloat(document.getElementById('hybSlider').value);
  const lstm  =parseFloat(document.getElementById('lstmSlider').value);
  await api('/api/threshold','POST',{hybrid,lstm});
  toast(`Thresholds updated: hybrid=${hybrid.toFixed(3)} lstm=${lstm.toFixed(2)}`,'success');
}

// ── Training ─────────────────────────────────────────────────────────────────
const _ds=[];
function addDsEntry(){
  const type=document.getElementById('dsType').value;
  const path=document.getElementById('dsPath').value.trim();
  if(!path){toast('Enter a dataset path','warning');return;}
  _ds.push({type,path});
  document.getElementById('dsPath').value='';
  renderDsEntries(); toast(`Added: ${type}`,'info');
}
function renderDsEntries(){
  const el=document.getElementById('datasetEntries'); if(!el)return;
  if(!_ds.length){el.innerHTML='<div style="color:var(--text3);font-size:.78rem;margin-bottom:.5rem">No datasets — will use synthetic data only</div>';return;}
  el.innerHTML=_ds.map((d,i)=>`
    <div class="ds-entry">
      <span class="ds-type">${d.type}</span>
      <span class="ds-path" title="${d.path}">${d.path}</span>
      <button class="del-btn" onclick="_ds.splice(${i},1);renderDsEntries()">✕</button>
    </div>`).join('');
}
async function startTrain(){
  const btn=document.getElementById('trainBtn');
  btn.disabled=true; btn.textContent='Training…';
  const inc=document.getElementById('optSyn')?.checked??true;
  const rows=parseInt(document.getElementById('maxRowsSlider').value)||150000;
  try{
    const r=await api('/api/train','POST',{datasets:_ds,include_synthetic:inc,max_rows:rows});
    const d=await r.json();
    if(d.success){toast('Training started','info');setPill('RUNNING');showProgress(true);pollTrain();}
    else{toast(d.error||'Failed','danger');btn.disabled=false;btn.textContent='🚀 Start Training';}
  }catch(e){toast('Error','danger');btn.disabled=false;btn.textContent='🚀 Start Training';}
}
function setPill(state){
  const el=document.getElementById('trainPill'); if(!el)return;
  el.textContent=state; el.className='status-pill '+state.toLowerCase();
}
function showProgress(show){
  const el=document.getElementById('trainProgress'); if(el)el.style.display=show?'block':'none';
}
function pollTrain(){
  clearInterval(S.trainPolling);
  S.trainPolling=setInterval(async()=>{
    try{
      const r=await api('/api/train/status');
      const d=await r.json();
      setText('trainTxt',d.progress||'Working…');
      if(!d.running){
        clearInterval(S.trainPolling);
        const btn=document.getElementById('trainBtn');
        if(btn){btn.disabled=false;btn.textContent='🚀 Start Training';}
        if(d.progress?.startsWith('ERROR')){setPill('ERROR');toast('Training failed','danger',8000);}
        else{setPill('DONE');showProgress(false);renderTrainResult(d.last_result);}
      }
    }catch(e){clearInterval(S.trainPolling);}
  },1500);
}
async function checkTrainStatus(){
  try{
    const r=await api('/api/train/status');
    const d=await r.json();
    if(d.running){setPill('RUNNING');showProgress(true);setText('trainTxt',d.progress||'');pollTrain();}
    if(d.last_result) renderTrainResult(d.last_result);
    renderDsEntries();
  }catch(e){}
}
function renderTrainResult(lr){
  if(!lr)return;
  const el=document.getElementById('trainResult'); if(!el)return;
  el.style.display='block';
  el.innerHTML=`
    <div style="background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.3);border-radius:6px;padding:.75rem;margin-top:.75rem;font-size:.82rem">
      ✅ <strong>Last training complete</strong><br/>
      Samples: ${(lr.n_samples||0).toLocaleString()} &nbsp;|&nbsp;
      Normal: ${(lr.n_normal||0).toLocaleString()} &nbsp;|&nbsp;
      Accuracy: <strong style="color:var(--green)">${((lr.accuracy||0)*100).toFixed(2)}%</strong> &nbsp;|&nbsp;
      CV-F1: <span style="color:var(--blue)">${((lr.cv_f1||0)*100).toFixed(2)}%</span>
    </div>`;
}

// ── WebSocket ──────────────────────────────────────────────────────────────
const socket = io({transports:['websocket','polling']});
socket.on('connect',    ()=>{ socket.emit('request_stats'); });
socket.on('disconnect', ()=>{ document.getElementById('sysStatusDot').className='status-dot'; setText('sysStatusText','Disconnected'); });
socket.on('new_packet', e  =>{ addMonRow(e); });
socket.on('new_alert',  a  =>{ addAlert(a); });
socket.on('stats_update',s =>{ renderStats(s); });
socket.on('training_done',r=>{ toast(`✅ Training done! Acc=${(r.accuracy*100).toFixed(1)}%`,'success',8000); renderTrainResult(r); setPill('DONE'); });

// ── Sound ──────────────────────────────────────────────────────────────────
let _audioCtx;
function playSound(){
  if(!S.sound)return;
  try{
    if(!_audioCtx) _audioCtx=new(window.AudioContext||window.webkitAudioContext)();
    const o=_audioCtx.createOscillator(), g=_audioCtx.createGain();
    o.connect(g); g.connect(_audioCtx.destination);
    o.type='sine'; o.frequency.setValueAtTime(880,_audioCtx.currentTime);
    g.gain.setValueAtTime(.12,_audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(.0001,_audioCtx.currentTime+.35);
    o.start(); o.stop(_audioCtx.currentTime+.35);
  }catch(e){}
}
function toggleSound(){
  S.sound=!S.sound;
  document.getElementById('soundBtn').textContent=S.sound?'🔊':'🔇';
  const el=document.getElementById('infoSound');
  if(el) el.textContent=S.sound?'On':'Off';
  toast(S.sound?'Alert sound ON':'Alert sound OFF','info');
}

// ── Auth ───────────────────────────────────────────────────────────────────
async function logout(){
  await api('/api/logout','POST');
  window.location.href='/login';
}

// ── Utilities ──────────────────────────────────────────────────────────────
function setText(id,val){const el=document.getElementById(id);if(el)el.textContent=val;}
function fmtN(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return String(n);}
function fmtT(ts){try{return new Date(ts).toLocaleTimeString('en-US',{hour12:false})}catch{return ts?.slice(11,19)||'—'}}
function mlBadge(v){return v===1?'<span class="badge badge-normal">NRM</span>':'<span class="badge badge-anom">ANM</span>';}
function resBadge(v){return v===1?'<span class="badge badge-normal">✓ NORMAL</span>':'<span class="badge badge-anom">⚠ ANOMALY</span>';}
async function api(url,method='GET',body=null){
  const opts={method,credentials:'include',headers:{'Content-Type':'application/json'}};
  if(body)opts.body=JSON.stringify(body);
  try{return await fetch(url,opts);}catch(e){return {ok:false,json:async()=>{}};}
}
function toast(msg,type='info',dur=3000){
  const c=document.getElementById('toasts');
  const el=document.createElement('div');
  el.className=`toast ${type}`; el.textContent=msg;
  c.appendChild(el); setTimeout(()=>el.remove(),dur);
}

// ── Init ────────────────────────────────────────────────────────────────────
(async()=>{
  try{
    const r=await api('/api/whoami');
    const d=await r.json();
    if(!d.logged_in){window.location.href='/login';return;}
    setText('userLbl',d.username||'admin');
    const av=document.getElementById('userAv');
    if(av) av.textContent=(d.username||'A')[0].toUpperCase();
  }catch(e){window.location.href='/login';return;}
  try{
    const r=await api('/api/live-data');
    if(r.ok) renderStats(await r.json());
  }catch(e){}
  try{
    const r=await api('/api/alerts?limit=50');
    if(r.ok){const data=await r.json();data.forEach(a=>addAlert(a));}
  }catch(e){}
  renderDsEntries();
  // Fallback polling when socket disconnected
  setInterval(async()=>{
    if(socket.connected)return;
    try{const r=await api('/api/stats');if(r.ok)renderStats(await r.json());}catch(e){}
  },3000);
})();

// ═══════════════════════════════════════════════════════════════
//  NEW FEATURES: Bytes formatter, AI Analysis, IP Manager GeoIP
// ═══════════════════════════════════════════════════════════════

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n >= 1048576) return (n/1048576).toFixed(1)+' MB';
  if (n >= 1024)    return (n/1024).toFixed(1)+' KB';
  return n+' B';
}

// ── AI Alert Analysis ─────────────────────────────────────────
async function analyzeAlert(idxOrObj) {
  const alert = (typeof idxOrObj === 'number') ? _alertStore[idxOrObj] : idxOrObj;
  if (!alert) { toast('Alert not found','warning'); return; }
  const panel   = document.getElementById('aiPanel');
  const content = document.getElementById('aiContent');
  if (!panel || !content) { toast('AI panel not found', 'warning'); return; }

  panel.style.display = 'block';
  content.innerHTML   = '<div style="color:var(--text2);padding:.5rem">🤖 Analyzing with AI…</div>';

  // Show panel centered
  panel.scrollTop = 0;

  try {
    const r = await api('/api/analyze', 'POST', alert);
    const d = await r.json();
    const srcTag = d.source === 'qwen-ai'
      ? '<span style="color:var(--blue);font-size:.7rem">⚡ Qwen AI</span>'
      : '<span style="color:var(--text3);font-size:.7rem">📋 Rule-based</span>';

    content.innerHTML = `
      <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.75rem">
        <strong style="font-size:.95rem">${d.title}</strong>
        ${srcTag}
        <span class="badge threat-${alert.threat_level||'High'}" style="margin-left:auto">${alert.threat_level||'High'}</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:.75rem">
        <div>
          <div style="color:var(--text3);font-size:.7rem;margin-bottom:.2rem">SOURCE IP</div>
          <div style="font-family:var(--mono);color:var(--blue)">${d.src_ip}</div>
          ${alert.src_flag ? `<div style="font-size:.75rem;color:var(--text2)">${alert.src_flag} ${alert.src_country||''} · ${alert.src_isp||''}</div>` : ''}
        </div>
        <div>
          <div style="color:var(--text3);font-size:.7rem;margin-bottom:.2rem">TARGET IP</div>
          <div style="font-family:var(--mono);color:var(--text2)">${d.dst_ip}</div>
        </div>
      </div>
      <div style="background:rgba(0,0,0,.2);border-radius:6px;padding:.75rem;margin-bottom:.5rem">
        <div style="color:var(--text3);font-size:.7rem;margin-bottom:.25rem">WHAT IS HAPPENING</div>
        <div>${d.what}</div>
      </div>
      <div style="background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.2);border-radius:6px;padding:.75rem;margin-bottom:.5rem">
        <div style="color:var(--red);font-size:.7rem;margin-bottom:.25rem">RISK</div>
        <div>${d.risk}</div>
      </div>
      <div style="background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.2);border-radius:6px;padding:.75rem;margin-bottom:.75rem">
        <div style="color:var(--green);font-size:.7rem;margin-bottom:.25rem">RECOMMENDED ACTIONS</div>
        <div style="white-space:pre-line">${d.action}</div>
      </div>
      <div style="display:flex;gap:.5rem">
        <button class="btn-danger" onclick="blockIpFromAlert('${d.src_ip}','${d.attack_type}')">🚫 Block ${d.src_ip}</button>
        <button class="btn-outline" onclick="closeAiPanel()">Dismiss</button>
      </div>`;
  } catch(e) {
    content.innerHTML = `<div style="color:var(--red)">Analysis failed: ${e.message}</div>`;
  }
}

function closeAiPanel() {
  const p = document.getElementById('aiPanel');
  if (p) p.style.display = 'none';
}

async function blockIpFromAlert(ip, reason) {
  await api('/api/blacklist', 'POST', {ip, reason});
  toast(`🚫 ${ip} blocked`, 'danger');
  closeAiPanel();
  if (S.page === 'network') loadLists();
}

// ── Enhanced IP Manager with GeoIP ───────────────────────────
function renderIpListWithGeo(id, items, type) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!items.length) {
    el.innerHTML = '<li class="empty-msg">Empty</li>'; return;
  }
  el.innerHTML = items.map(it => `
    <li style="flex-wrap:wrap;gap:.3rem">
      <span class="ip-addr">${it.ip_address}</span>
      ${it.country ? `<span style="font-size:.7rem;color:var(--text2)">${it.flag||'🌐'} ${it.country}</span>` : ''}
      ${it.isp     ? `<span style="font-size:.68rem;color:var(--text3);flex:1">${it.isp}</span>` : ''}
      <span class="ip-reason" style="font-size:.68rem">${it.reason||''}</span>
      <button class="del-btn" onclick="removeIp('${type}','${it.ip_address}')">✕</button>
    </li>`).join('');
}

// Override loadLists to enrich with GeoIP
async function loadLists() {
  const [bl, wl] = await Promise.all([
    api('/api/blacklist').then(r => r.json()).catch(() => []),
    api('/api/whitelist').then(r => r.json()).catch(() => []),
  ]);

  // Enrich with GeoIP
  async function enrichList(items) {
    return Promise.all(items.map(async it => {
      try {
        const r = await api(`/api/geoip/${it.ip_address}`);
        const geo = await r.json();
        return {...it, ...geo};
      } catch { return it; }
    }));
  }

  const [blGeo, wlGeo] = await Promise.all([enrichList(bl), enrichList(wl)]);
  renderIpListWithGeo('blList', blGeo, 'blacklist');
  renderIpListWithGeo('wlList', wlGeo, 'whitelist');
}

// Also show GeoIP when user types an IP in the input
async function lookupInputGeo(inputId, displayId) {
  const ip = document.getElementById(inputId)?.value?.trim();
  if (!ip || ip.length < 7) return;
  try {
    const r = await api(`/api/geoip/${ip}`);
    const g = await r.json();
    const el = document.getElementById(displayId);
    if (el) el.textContent = `${g.flag||'🌐'} ${g.country||'—'} · ${g.isp||'—'}`;
  } catch {}
}

async function checkDB() {
  try {
    const r = await api('/api/db-status');
    const d = await r.json();
    if (d.connected) {
      toast('✅ MySQL connected! Packets: ' + (d.total_packets||0), 'success', 4000);
    } else {
      toast('⚠ MySQL not connected. Copy .env.example to .env and set DB_PASSWORD', 'warning', 6000);
    }
  } catch(e) { toast('DB check failed', 'danger'); }
}
