#!/usr/bin/env python3
"""
Membuat BENCHMARK.html: dashboard interaktif hasil pengujian PQC (self-contained).

Jalankan:
    python build_benchmark.py --db ../server/results.db --out ./analysis_output/BENCHMARK.html
Boleh beberapa database sekaligus (data digabung):
    python build_benchmark.py --db a.db b.db
"""
import argparse
import datetime
import json
import random
import sqlite3
import statistics
from pathlib import Path

ALIAS = {
    "SLH_DSA_PURE_SHAKE_128S": "SLH-DSA-SHAKE-128s",
    "SLH_DSA_PURE_SHAKE_192S": "SLH-DSA-SHAKE-192s",
    "SLH_DSA_PURE_SHAKE_256S": "SLH-DSA-SHAKE-256s",
}
COLS = ["keygen_time_ms", "encaps_time_ms", "server_encaps_time_ms", "decaps_time_ms", "sign_time_ms",
        "verify_time_ms", "server_verify_time_ms", "network_rtt_ms",
        "pk_size_bytes", "ct_size_bytes", "ss_size_bytes", "sig_size_bytes"]
DERIVED = {  # pemakaian heap = sebelum - sesudah (hanya ada jika data dari ESP32)
    "heap_keygen_used": ("heap_before_keygen", "heap_after_keygen"),
    "heap_decaps_used": ("heap_before_decaps", "heap_after_decaps"),
    "heap_encaps_used": ("heap_before_encaps", "heap_after_encaps"),
    "heap_sign_used":   ("heap_before_sign", "heap_after_sign"),
}


ENERGY = [("energy_keygen_mj", "keygen_time_ms", "net_energy_keygen_mj"),
          ("energy_encaps_mj", "encaps_time_ms", "net_energy_encaps_mj"),
          ("energy_decaps_mj", "decaps_time_ms", "net_energy_decaps_mj"),
          ("energy_sign_mj", "sign_time_ms", "net_energy_sign_mj"),
          ("energy_verify_mj", "verify_time_ms", "net_energy_verify_mj")]
ENERGY_STATE = {"want_demo": False, "demo": False}


def inject_demo_energy(rows, seed=7):
    """DATA SINTETIS: hanya untuk melihat bentuk grafik energi sebelum INA219 tersedia."""
    if any(r.get(e) is not None for r in rows for e, _, _ in ENERGY):
        print("[lewati] --demo-energy: database sudah berisi data energi asli.")
        return
    rng = random.Random(seed)
    for r in rows:
        if r.get("status") != "success":
            continue
        idle = rng.gauss(450.0, 15.0)
        r["idle_power_mw"] = idle
        for e, t, _ in ENERGY:
            if r.get(t) is not None:
                r[e] = (idle + max(rng.gauss(120.0, 15.0), 10.0)) * float(r[t]) / 1000.0
    ENERGY_STATE["demo"] = True
    print("!! PERINGATAN: --demo-energy aktif. Kolom energi SINTETIS, bukan hasil pengukuran. !!")


def family(name):
    for f in ("ML-KEM", "HQC", "ML-DSA", "SLH-DSA"):
        if name.startswith(f):
            return f
    return "?"


def load(dbs):
    rows = []
    for p in dbs:
        if not Path(p).exists():
            raise SystemExit(f"Error: database tidak ditemukan: {p}")
        conn = sqlite3.connect(p)
        conn.row_factory = sqlite3.Row
        rows += [dict(r) for r in conn.execute("SELECT * FROM trials")]
        conn.close()
    if not rows:
        raise SystemExit("Error: tidak ada data pengujian")
    return rows


def stats(vals):
    n = len(vals)
    return {"n": n, "mean": statistics.fmean(vals), "median": statistics.median(vals),
            "std": statistics.stdev(vals) if n > 1 else 0.0,
            "min": min(vals), "max": max(vals), "raw": [round(v, 4) for v in vals]}


def normalize(rows):
    """Protokol lama (1 ronde): Encaps diukur di PC, bukan di ESP32."""
    for r in rows:
        if r.get("operation_type", "kem") == "kem" and (r.get("kem_rounds") or 1) < 2:
            if r.get("server_encaps_time_ms") is None:
                r["server_encaps_time_ms"] = r.get("encaps_time_ms")
            r["encaps_time_ms"] = None
    if ENERGY_STATE["want_demo"]:
        inject_demo_energy(rows)
    return rows


def build(rows):
    rows = normalize(rows)
    algos = {}
    tid_seen = {}  # trial_id berbeda per algoritma (satu trial bisa punya beberapa baris retry)
    for r in rows:
        name = ALIAS.get(r["algorithm"], r["algorithm"])
        a = algos.setdefault(name, {"family": family(name), "trials": 0, "ok": 0, "vals": {}})
        tid = r.get("trial_id")
        tid_seen.setdefault(name, set()).add(tid if tid is not None else id(r))
        a["trials"] = len(tid_seen[name])
        if r.get("status") != "success":
            continue
        a["ok"] += 1
        for c in COLS:
            if r.get(c) is not None:
                a["vals"].setdefault(c, []).append(float(r[c]))
        for k, (b, af) in DERIVED.items():
            if r.get(b) is not None and r.get(af) is not None:
                a["vals"].setdefault(k, []).append(float(r[b]) - float(r[af]))
        idle = r.get("idle_power_mw")
        for e, t, key in ENERGY:   # energi bersih (mJ) = energi - idle_mW * durasi_ms / 1000
            if r.get(e) is not None and r.get(t) is not None and idle is not None:
                a["vals"].setdefault(key, []).append(float(r[e]))
    out = {}
    for name, a in algos.items():
        out[name] = {"family": a["family"], "trials": a["trials"], "ok": a["ok"],
                     "metrics": {k: stats(v) for k, v in a["vals"].items() if v}}
    has_esp = any(r.get("heap_before_keygen") is not None for r in rows)
    return {"algos": out, "source": "ESP32" if has_esp else "Simulasi PC",
            "generated": datetime.datetime.now().strftime("%d %b %Y %H:%M"),
            "energy_demo": ENERGY_STATE["demo"]}


HTML = r"""<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Benchmark PQC pada ESP32-WROOM-32</title>
<style>
:root{--bg:#f7f6f2;--card:#fff;--ink:#1d2421;--mut:#68716c;--line:#e2e0d8;--a:#1F5C4F;--b:#C2410C}
@media(prefers-color-scheme:dark){:root{--bg:#141816;--card:#1d2321;--ink:#e8ece9;--mut:#9aa5a0;--line:#2e3633;--a:#4FB89E;--b:#F08A5D}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 18px 60px}
h1{font:700 27px Georgia,serif;margin:0 0 4px}
h2{font:700 17px Georgia,serif;margin:0 0 4px}
.sub,.mut{color:var(--mut)}
.sub{margin:0 0 16px}
.hint{color:var(--mut);font-size:13.5px;margin:0 0 10px}
.banner{background:#fff4d6;color:#5a4300;border:1px solid #e8cf87;border-radius:10px;padding:10px 14px;margin-bottom:16px;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.card b{display:block;font-size:23px}.card span{color:var(--mut);font-size:13px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:18px}
details.panel summary{cursor:pointer;font-weight:600}
details.panel ul{margin:10px 0 0}
.tabs{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.tab{border:1px solid var(--line);background:transparent;color:var(--ink);padding:8px 16px;border-radius:999px;cursor:pointer;font:inherit}
.tab.on{background:var(--a);border-color:var(--a);color:#fff}
.ctrl{display:flex;gap:14px 18px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
select,.btn{font:inherit;padding:6px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink)}
.btn{cursor:pointer}.btn:hover{border-color:var(--a)}
.right{margin-left:auto}
.tag{font-size:12px;color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:2px 10px}
.legend{display:flex;gap:18px;margin:6px 0;font-size:14px}
.legend i,.dot{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}
svg{width:100%;height:auto;display:block}
svg text{fill:var(--mut);font-size:12px}
svg .val{fill:var(--ink);font-weight:600}
svg .lbl{fill:var(--ink)}
.hov{cursor:pointer}.hov:hover{opacity:.75}
#tip{position:fixed;pointer-events:none;background:#1d2421;color:#fff;font-size:13px;padding:8px 11px;border-radius:8px;display:none;z-index:9;line-height:1.5}
.cmpgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:14px}
.cmp{border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.cmp .lv{display:block;color:var(--mut);font-size:12.5px}
.cmp b{display:block;font:700 26px Georgia,serif}
.cmp span.tx{font-size:13.5px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}
th{color:var(--mut);font-weight:600}
td:first-child{font-family:ui-monospace,Consolas,monospace}
</style></head><body><div class="wrap">
<h1>Benchmark PQC pada ESP32-WROOM-32</h1>
<p class="sub">ML-KEM vs HQC (key establishment) dan ML-DSA vs SLH-DSA (digital signature).</p>
<div id="banner"></div>
<div class="cards" id="cards"></div>
<details class="panel"><summary>Cara membaca halaman ini</summary>
<ul>
<li><b>Batang</b> = nilai tiap algoritma. Hijau dan oranye adalah dua keluarga yang dibandingkan pada tingkat keamanan setara.</li>
<li><b>Garis hitam di batang</b> = sebaran data. Pada mode <i>Rata-rata ± std</i> garis menunjukkan simpangan baku; pada mode <i>Median</i> garis menunjukkan nilai terkecil sampai terbesar.</li>
<li><b>Skala logaritmik</b> membuat batang yang sangat kecil tetap terlihat saat ada yang ratusan kali lebih besar. Tiap garis kisi bernilai 10× garis di bawahnya.</li>
<li><b>Arahkan kursor</b> ke batang atau titik untuk melihat angka lengkapnya.</li>
<li><b>Median</b> lebih tahan terhadap satu trial yang tiba-tiba lambat (misalnya trial pertama), jadi cocok bila rata-rata terasa tidak mewakili.</li>
</ul></details>
<div class="panel">
  <div class="tabs" id="tabs"></div>
  <div class="ctrl">
    <label>Metrik <select id="metric"></select></label>
    <label>Statistik <select id="mode"><option value="mean">Rata-rata ± std</option><option value="median">Median &amp; rentang min–maks</option></select></label>
    <label><input type="checkbox" id="log"> Skala logaritmik</label>
    <span class="tag" id="where"></span>
    <button class="btn right" id="csv">Unduh CSV</button>
  </div>
  <div class="legend" id="legend"></div>
  <div id="enote"></div>
  <div id="chart"></div>
  <div class="cmpgrid" id="cmp"></div>
</div>
<div class="panel"><h2>Sebaran tiap trial</h2>
  <p class="hint">Satu titik = satu trial. Garis pendek menandai median. Berguna untuk melihat apakah hasilnya konsisten atau ada trial yang menyimpang.</p>
  <div id="strip"></div></div>
<div class="panel"><h2>Trade-off: waktu komputasi vs data yang dikirim</h2>
  <p class="hint" id="scNote"></p>
  <div id="scatter"></div></div>
<div class="panel"><h2>Tabel detail</h2><div class="scroll"><table id="tbl"></table></div></div>
<p class="mut" style="font-size:13px">Dibuat otomatis: <span id="gen"></span></p>
</div><div id="tip"></div>
<script>
const D = __DATA__;
const A = D.algos;
const $ = id => document.getElementById(id);
const M = (n, k) => A[n] && A[n].metrics[k];
const dec = (v, d) => v.toFixed(d).replace(".", ",");
const fmt = v => v >= 1000 ? Math.round(v).toLocaleString("id-ID") : v >= 100 ? dec(v, 0) : v >= 10 ? dec(v, 1) : v >= 0.1 ? dec(v, 2) : String(+v.toPrecision(2)).replace(".", ",");
const tf = v => v >= 1000 ? v.toLocaleString("id-ID") : String(+v.toPrecision(3)).replace(".", ",");
const hum = v => v >= 60000 ? dec(v / 60000, 1) + " menit" : v >= 1000 ? dec(v / 1000, 2) + " detik" : fmt(v) + " ms";
const short = n => n.replace("SLH-DSA-SHAKE-", "SLH-");

const TABS = {
  kem: { title: "Key Establishment", fam: ["ML-KEM", "HQC"],
    levels: ["Level 1", "Level 3", "Level 5"],
    pairs: [["ML-KEM-512", "HQC-1"], ["ML-KEM-768", "HQC-3"], ["ML-KEM-1024", "HQC-5"]],
    cpu: ["keygen_time_ms", "encaps_time_ms", "decaps_time_ms"], size: ["pk_size_bytes", "ct_size_bytes"],
    cpuL: "KeyGen + Encaps + Decaps", sizeL: "public key + ciphertext",
    metrics: [
      { k: "keygen_time_ms", l: "Waktu KeyGen", u: "ms", w: "diukur di ESP32" },
      { k: "decaps_time_ms", l: "Waktu Decaps", u: "ms", w: "diukur di ESP32" },
      { k: "encaps_time_ms", l: "Waktu Encaps", u: "ms", w: "diukur di ESP32 (ronde 2)" },
      { k: "server_encaps_time_ms", l: "Waktu Encaps (server, pembanding)", u: "ms", w: "diukur di server PC" },
      { k: "network_rtt_ms", l: "Total waktu 1 siklus (RTT)", u: "ms", w: "ESP32 ↔ server" },
      { k: "pk_size_bytes", l: "Ukuran public key", u: "byte", w: "ukuran data" },
      { k: "ct_size_bytes", l: "Ukuran ciphertext", u: "byte", w: "ukuran data" },
      { k: "heap_keygen_used", l: "Heap terpakai saat KeyGen", u: "byte", w: "diukur di ESP32" },
      { k: "heap_decaps_used", l: "Heap terpakai saat Decaps", u: "byte", w: "diukur di ESP32" },
      { k: "heap_encaps_used", l: "Heap terpakai saat Encaps", u: "byte", w: "diukur di ESP32" },
      { k: "net_energy_keygen_mj", l: "Energi bersih KeyGen", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_encaps_mj", l: "Energi bersih Encaps", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_decaps_mj", l: "Energi bersih Decaps", u: "mJ", w: "INA219 dikurangi daya idle" } ] },
  sig: { title: "Digital Signature", fam: ["ML-DSA", "SLH-DSA"],
    levels: ["44 ↔ 128s", "65 ↔ 192s", "87 ↔ 256s"],
    pairs: [["ML-DSA-44", "SLH-DSA-SHAKE-128s"], ["ML-DSA-65", "SLH-DSA-SHAKE-192s"], ["ML-DSA-87", "SLH-DSA-SHAKE-256s"]],
    cpu: ["keygen_time_ms", "sign_time_ms", "verify_time_ms"], size: ["pk_size_bytes", "sig_size_bytes"],
    cpuL: "KeyGen + Sign + Verify", sizeL: "public key + signature",
    metrics: [
      { k: "keygen_time_ms", l: "Waktu KeyGen", u: "ms", w: "diukur di ESP32" },
      { k: "sign_time_ms", l: "Waktu Sign", u: "ms", w: "diukur di ESP32" },
      { k: "verify_time_ms", l: "Waktu Verify (lokal)", u: "ms", w: "diukur di ESP32" },
      { k: "server_verify_time_ms", l: "Waktu Verify (server)", u: "ms", w: "diukur di server PC" },
      { k: "network_rtt_ms", l: "Total waktu 1 siklus (RTT)", u: "ms", w: "ESP32 ↔ server" },
      { k: "pk_size_bytes", l: "Ukuran public key", u: "byte", w: "ukuran data" },
      { k: "sig_size_bytes", l: "Ukuran signature", u: "byte", w: "ukuran data" },
      { k: "heap_keygen_used", l: "Heap terpakai saat KeyGen", u: "byte", w: "diukur di ESP32" },
      { k: "heap_sign_used", l: "Heap terpakai saat Sign", u: "byte", w: "diukur di ESP32" },
      { k: "net_energy_keygen_mj", l: "Energi bersih KeyGen", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_sign_mj", l: "Energi bersih Sign", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_verify_mj", l: "Energi bersih Verify", u: "mJ", w: "INA219 dikurangi daya idle" } ] }
};
let tab = "kem", cur = [], mode = "mean";

const val = s => mode === "mean" ? s.mean : s.median;
const wlo = s => mode === "mean" ? Math.max(s.mean - s.std, 0) : s.min;
const whi = s => mode === "mean" ? s.mean + s.std : s.max;
const avail = T => T.metrics.filter(m => T.pairs.flat().some(n => M(n, m.k)));
const fam = (T, n) => Math.max(0, T.fam.indexOf(A[n].family));
const colr = i => i ? "var(--b)" : "var(--a)";

function scale(vals, log, Tp, ph) {
  const mx = Math.max(...vals) * 1.12;
  let lo = 0, hi = mx, ticks = [];
  if (log) {
    const mn = Math.min(...vals.filter(v => v > 0));
    lo = Math.pow(10, Math.floor(Math.log10(mn)));
    hi = Math.pow(10, Math.ceil(Math.log10(mx)));
    if (hi <= lo) hi = lo * 10;
    for (let e = Math.round(Math.log10(lo)); e <= Math.round(Math.log10(hi)); e++) ticks.push(Math.pow(10, e));
  } else {
    const raw = mx / 5, mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const st = [1, 2, 2.5, 5, 10].find(x => x * mag >= raw) * mag;
    hi = Math.ceil(mx / st) * st;
    for (let v = 0; v <= hi + 1e-9; v += st) ticks.push(v);
  }
  const Y = v => log
    ? Tp + ph * (1 - (Math.log(Math.max(v, lo)) - Math.log(lo)) / (Math.log(hi) - Math.log(lo)))
    : Tp + ph * (1 - v / hi);
  return { Y, ticks };
}

const tipFor = (n, m) => {
  const s = M(n, m.k);
  const h = m.u === "ms" && s.mean >= 1000 ? " (≈ " + hum(s.mean) + ")" : "";
  return `<b>${n}</b><br>rata-rata ${fmt(s.mean)} ± ${fmt(s.std)} ${m.u}${h}<br>median ${fmt(s.median)} · min ${fmt(s.min)} · maks ${fmt(s.max)}<br>${s.n} trial`;
};

function barChart(T, m, log) {
  const W = 920, H = 400, L = 72, R = 16, Tp = 26, B = 60, pw = W - L - R, ph = H - Tp - B;
  const all = [];
  T.pairs.flat().forEach(n => { const s = M(n, m.k); if (s) { all.push(val(s), whi(s)); } });
  const sc = scale(all.filter(v => v > 0), log, Tp, ph), Y = sc.Y, base = Tp + ph;
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  sc.ticks.forEach(t => {
    const y = Y(t);
    s += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${L - 8}" y="${y + 4}" text-anchor="end">${tf(t)}</text>`;
  });
  s += `<text transform="translate(16 ${Tp + ph / 2}) rotate(-90)" text-anchor="middle">${m.u}${log ? " (skala log)" : ""}</text>`;
  const gw = pw / T.pairs.length, bw = Math.min(74, gw / 3.2);
  T.pairs.forEach((p, i) => {
    const x0 = L + gw * i + gw / 2;
    p.forEach((n, j) => {
      const bx = j === 0 ? x0 - bw - 4 : x0 + 4, st = M(n, m.k);
      if (!st) { s += `<text x="${bx + bw / 2}" y="${base - 6}" text-anchor="middle">n/a</text>`; return; }
      const v = val(st), y = Y(v);
      s += `<rect class="hov" data-tip="${tipFor(n, m)}" x="${bx}" y="${y}" width="${bw}" height="${Math.max(base - y, 1)}" rx="3" style="fill:${colr(j)}"/>`;
      let labY = y - 6;
      const hiV = whi(st), loV = wlo(st);
      if (hiV > loV) {
        const yt = Y(hiV), yb = Y(loV), cx = bx + bw / 2;
        s += `<g stroke="var(--ink)" stroke-width="1.4" opacity=".7" pointer-events="none"><line x1="${cx}" x2="${cx}" y1="${yt}" y2="${yb}"/><line x1="${cx - 5}" x2="${cx + 5}" y1="${yt}" y2="${yt}"/><line x1="${cx - 5}" x2="${cx + 5}" y1="${yb}" y2="${yb}"/></g>`;
        labY = Math.min(labY, yt - 6);
      }
      s += `<text class="val" x="${bx + bw / 2}" y="${labY}" text-anchor="middle">${fmt(v)}</text>`;
    });
    s += `<text class="lbl" x="${x0}" y="${base + 20}" text-anchor="middle" style="font-weight:600">${T.levels[i]}</text>`;
    s += `<text x="${x0}" y="${base + 37}" text-anchor="middle">${p[0]} vs ${short(p[1])}</text>`;
  });
  return s + "</svg>";
}

function cmpCards(T, m) {
  const out = [];
  T.pairs.forEach((p, i) => {
    const a = M(p[0], m.k), b = M(p[1], m.k);
    if (!a || !b) return;
    const va = val(a), vb = val(b);
    if (va <= 0 || vb <= 0) return;
    const r = va / vb, x = r <= 1 ? 1 / r : r, low = r <= 1 ? 0 : 1;
    const head = x < 1.05 ? "≈ setara" : dec(x, 1) + "×";
    const body = x < 1.05 ? `${p[0]} ≈ ${p[1]}`
      : `<i class="dot" style="background:${colr(low)}"></i>${p[low]} lebih rendah dari ${p[1 - low]}`;
    out.push(`<div class="cmp"><span class="lv">${T.levels[i]}</span><b>${head}</b><span class="tx">${body}</span></div>`);
  });
  return out.join("");
}

function stripChart(T, m, log) {
  const names = T.pairs.flat().filter(n => M(n, m.k));
  const W = 920, H = 300, L = 72, R = 16, Tp = 16, B = 56, pw = W - L - R, ph = H - Tp - B;
  const all = [];
  names.forEach(n => M(n, m.k).raw.forEach(v => all.push(v)));
  const sc = scale(all.filter(v => v > 0), log, Tp, ph), Y = sc.Y, base = Tp + ph;
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  sc.ticks.forEach(t => {
    const y = Y(t);
    s += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${L - 8}" y="${y + 4}" text-anchor="end">${tf(t)}</text>`;
  });
  s += `<text transform="translate(16 ${Tp + ph / 2}) rotate(-90)" text-anchor="middle">${m.u}${log ? " (skala log)" : ""}</text>`;
  const gw = pw / names.length;
  names.forEach((n, i) => {
    const st = M(n, m.k), cx = L + gw * i + gw / 2, c = colr(fam(T, n));
    st.raw.forEach((v, j) => {
      const jx = ((j * 37) % 11 - 5) * Math.min(5, gw / 24);
      s += `<circle class="hov" data-tip="<b>${n}</b><br>trial ke-${j + 1}: ${fmt(v)} ${m.u}" cx="${cx + jx}" cy="${Y(v)}" r="4.5" style="fill:${c}" opacity=".75"/>`;
    });
    const ym = Y(st.median);
    s += `<line x1="${cx - 22}" x2="${cx + 22}" y1="${ym}" y2="${ym}" stroke="var(--ink)" stroke-width="2" pointer-events="none"/>`;
    s += `<text x="${cx}" y="${base + 20}" text-anchor="middle" class="lbl" style="font-size:11.5px">${short(n)}</text>`;
  });
  return s + "</svg>";
}

function scatterChart(T) {
  const names = T.pairs.flat().filter(n => {
    return T.cpu.every(k => M(n, k)) && T.size.every(k => M(n, k));
  });
  if (!names.length) return '<p class="mut">Data belum lengkap untuk grafik ini.</p>';
  const P = names.map(n => ({
    n, f: fam(T, n),
    x: T.size.reduce((a, k) => a + val(M(n, k)), 0),
    y: T.cpu.reduce((a, k) => a + val(M(n, k)), 0)
  }));
  const W = 920, H = 380, L = 72, R = 24, Tp = 16, B = 52, pw = W - L - R, ph = H - Tp - B;
  const sy = scale(P.map(p => p.y), true, Tp, ph), sx = scale(P.map(p => p.x), true, 0, pw);
  const X = v => L + pw - sx.Y(v), Y = sy.Y;
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  sy.ticks.forEach(t => { const y = Y(t); s += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${L - 8}" y="${y + 4}" text-anchor="end">${tf(t)}</text>`; });
  sx.ticks.forEach(t => { const x = X(t); s += `<line y1="${Tp}" y2="${Tp + ph}" x1="${x}" x2="${x}" stroke="var(--line)"/><text x="${x}" y="${Tp + ph + 18}" text-anchor="middle">${tf(t)}</text>`; });
  s += `<text transform="translate(16 ${Tp + ph / 2}) rotate(-90)" text-anchor="middle">waktu komputasi, ms (${T.cpuL})</text>`;
  s += `<text x="${L + pw / 2}" y="${H - 8}" text-anchor="middle">data dikirim lewat jaringan, byte (${T.sizeL})</text>`;
  P.forEach(p => {
    const x = X(p.x), y = Y(p.y), left = x > W - 150;
    const extra = p.y >= 1000 ? " (≈ " + hum(p.y) + ")" : "";
    s += `<circle class="hov" data-tip="<b>${p.n}</b><br>waktu ${fmt(p.y)} ms${extra}<br>data ${fmt(p.x)} byte" cx="${x}" cy="${y}" r="8" style="fill:${colr(p.f)}" opacity=".85"/>`;
    s += `<text class="lbl" x="${left ? x - 12 : x + 12}" y="${y + 4}" text-anchor="${left ? "end" : "start"}" style="font-size:11.5px" pointer-events="none">${short(p.n)}</text>`;
  });
  return s + "</svg>";
}

function render() {
  const T = TABS[tab], m = cur[+$("metric").value];
  $("scNote").textContent = "Makin ke kiri-bawah, makin ringan di waktu dan di jaringan. Kedua sumbu berskala logaritmik.";
  $("scatter").innerHTML = scatterChart(T);
  if (!m) {
    $("chart").innerHTML = '<p class="mut">Belum ada data untuk kelompok ini pada database yang dimuat.</p>';
    $("cmp").innerHTML = ""; $("strip").innerHTML = ""; $("tbl").innerHTML = ""; $("where").textContent = ""; $("legend").innerHTML = "";
    return;
  }
  const log = $("log").checked;
  $("where").textContent = m.w;
  $("legend").innerHTML = T.fam.map((f, i) => `<span><i style="background:${colr(i)}"></i>${f}</span>`).join("");
  $("chart").innerHTML = barChart(T, m, log);
  const neg = m.k.indexOf("net_energy") === 0 ? T.pairs.flat().filter(n => M(n, m.k) && M(n, m.k).mean <= 0) : [];
  $("enote").innerHTML = neg.length ? `<p class="hint">Energi bersih &le; 0 pada: ${neg.join(", ")}. Operasi terlalu singkat untuk dibedakan dari daya idle; perbanyak pengulangan di firmware.</p>` : "";
  $("cmp").innerHTML = cmpCards(T, m);
  $("strip").innerHTML = stripChart(T, m, log);
  const rows = T.pairs.flat().filter(n => A[n]).map(n => {
    const a = A[n], s = M(n, m.k), c = f => s ? fmt(s[f]) : "–";
    return `<tr><td>${n}</td><td>${a.family}</td><td>${a.ok}/${a.trials}</td><td>${c("mean")}</td><td>${c("std")}</td><td>${c("median")}</td><td>${c("min")}</td><td>${c("max")}</td></tr>`;
  }).join("");
  $("tbl").innerHTML = `<tr><th>Algoritma</th><th>Keluarga</th><th>Trial sukses</th><th>Mean (${m.u})</th><th>Std</th><th>Median</th><th>Min</th><th>Maks</th></tr>${rows}`;
}

function autoLog() {
  const T = TABS[tab], m = cur[+$("metric").value];
  if (!m) return;
  const v = T.pairs.flat().map(n => M(n, m.k)).filter(Boolean).map(s => s.mean).filter(x => x > 0);
  $("log").checked = v.length > 1 && Math.max(...v) / Math.min(...v) > 30;
}

function setTab(t) {
  tab = t;
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("on", b.dataset.t === t));
  cur = avail(TABS[t]);
  $("metric").innerHTML = cur.map((m, i) => `<option value="${i}">${m.l}</option>`).join("");
  autoLog(); render();
}

function downloadCSV() {
  const rows = [["algoritma", "keluarga", "trial_sukses", "trial_total", "metrik", "mean", "std", "median", "min", "maks"]];
  Object.keys(A).sort().forEach(n => {
    const a = A[n];
    Object.entries(a.metrics).forEach(([k, s]) => rows.push([n, a.family, a.ok, a.trials, k, s.mean, s.std, s.median, s.min, s.max]));
  });
  const blob = new Blob([rows.map(r => r.join(",")).join("\n")], { type: "text/csv" });
  const l = document.createElement("a");
  l.href = URL.createObjectURL(blob); l.download = "benchmark_pqc.csv"; l.click();
}

(function init() {
  const all = Object.values(A), ok = all.reduce((s, a) => s + a.ok, 0), tot = all.reduce((s, a) => s + a.trials, 0);
  $("cards").innerHTML = [[tot, "total trial"], [all.length, "algoritma diuji"],
    [(100 * ok / tot).toFixed(1).replace(".", ",") + "%", "success rate"], [D.source, "sumber data"],
    [D.energy_demo ? "DEMO" : (Object.values(A).some(a => Object.keys(a.metrics).some(k => k.indexOf("net_energy") === 0)) ? "INA219" : "belum ada"), "data energi"]]
    .map(c => `<div class="card"><b>${c[0]}</b><span>${c[1]}</span></div>`).join("");
  if (D.source !== "ESP32")
    $("banner").innerHTML = '<div class="banner"><b>Data simulasi PC.</b> Angka di sini bukan hasil ESP32 (jauh lebih cepat). Gunakan untuk memeriksa tampilan saja; data asli akan menggantikannya setelah hardware diuji.</div>';
  $("tabs").innerHTML = Object.entries(TABS).map(([k, T]) => `<button class="tab" data-t="${k}">${T.title}</button>`).join("");
  if (D.energy_demo)
    $("banner").innerHTML += '<div class="banner" style="background:#fde2e2;color:#7a1212;border-color:#e5a3a3"><b>ENERGI DEMO (sintetis).</b> Kolom energi dibuat otomatis hanya untuk melihat bentuk tampilan. Bukan hasil pengukuran INA219.</div>';
  document.querySelectorAll(".tab").forEach(b => b.onclick = () => setTab(b.dataset.t));
  $("metric").onchange = () => { autoLog(); render(); };
  $("mode").onchange = () => { mode = $("mode").value; render(); };
  $("log").onchange = render;
  $("csv").onclick = downloadCSV;
  $("gen").textContent = D.generated;
  const tip = $("tip");
  document.addEventListener("mousemove", e => {
    const t = e.target.dataset && e.target.dataset.tip;
    if (!t) { tip.style.display = "none"; return; }
    tip.innerHTML = t; tip.style.display = "block";
    tip.style.left = Math.min(e.clientX + 14, innerWidth - 230) + "px";
    tip.style.top = (e.clientY + 14) + "px";
  });
  setTab("kem");
})();
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="Bangun BENCHMARK.html dari database hasil pengujian")
    ap.add_argument("--db", nargs="+", default=["../server/results.db"])
    ap.add_argument("--out", default="./analysis_output/BENCHMARK.html")
    ap.add_argument("--demo-energy", action="store_true",
                    help="isi kolom energi SINTETIS untuk uji tampilan (bukan hasil ukur)")
    args = ap.parse_args()
    ENERGY_STATE["want_demo"] = args.demo_energy

    data = build(load(args.db))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(HTML.replace("__DATA__", json.dumps(data)), encoding="utf-8")
    print(f"Algoritma ditemukan : {', '.join(sorted(data['algos']))}")
    print(f"Sumber data         : {data['source']}")
    print(f"BENCHMARK.html      : {out.resolve()}")


if __name__ == "__main__":
    main()
