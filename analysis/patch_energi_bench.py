import sys
from pathlib import Path

PATH = Path(sys.argv[1] if len(sys.argv) > 1 else "build_benchmark.py")
s = PATH.read_text()

PAIRS = []

# 1. import random
PAIRS.append(("import json\n", "import json\nimport random\n"))

# 2. definisi energi + generator data demo
PAIRS.append(("def family(name):\n", r'''ENERGY = [("energy_keygen_mj", "keygen_time_ms", "net_energy_keygen_mj"),
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
'''))

# 3. demo disuntik setelah normalisasi
PAIRS.append(('            r["encaps_time_ms"] = None\n    return rows\n',
              '            r["encaps_time_ms"] = None\n    if ENERGY_STATE["want_demo"]:\n        inject_demo_energy(rows)\n    return rows\n'))

# 4. hitung energi bersih per trial
PAIRS.append(('                a["vals"].setdefault(k, []).append(float(r[b]) - float(r[af]))\n    out = {}\n',
              r'''                a["vals"].setdefault(k, []).append(float(r[b]) - float(r[af]))
        idle = r.get("idle_power_mw")
        for e, t, key in ENERGY:   # energi bersih (mJ) = energi - idle_mW * durasi_ms / 1000
            if r.get(e) is not None and r.get(t) is not None and idle is not None:
                a["vals"].setdefault(key, []).append(float(r[e]) - float(idle) * float(r[t]) / 1000.0)
    out = {}
'''))

# 5. penanda demo di data
PAIRS.append(('            "generated": datetime.datetime.now().strftime("%d %b %Y %H:%M")}\n',
              '            "generated": datetime.datetime.now().strftime("%d %b %Y %H:%M"),\n            "energy_demo": ENERGY_STATE["demo"]}\n'))

# 6-7. opsi --demo-energy
PAIRS.append(('    ap.add_argument("--out", default="./analysis_output/BENCHMARK.html")\n',
              '    ap.add_argument("--out", default="./analysis_output/BENCHMARK.html")\n'
              '    ap.add_argument("--demo-energy", action="store_true",\n'
              '                    help="isi kolom energi SINTETIS untuk uji tampilan (bukan hasil ukur)")\n'))
PAIRS.append(('    args = ap.parse_args()\n',
              '    args = ap.parse_args()\n    ENERGY_STATE["want_demo"] = args.demo_energy\n'))

# 8. format angka kecil (energi bisa 0,004 mJ)
PAIRS.append(('v >= 10 ? dec(v, 1) : dec(v, 2);',
              'v >= 10 ? dec(v, 1) : v >= 0.1 ? dec(v, 2) : String(+v.toPrecision(2)).replace(".", ",");'))

# 9-10. metrik energi di dua tab
PAIRS.append(('      { k: "heap_encaps_used", l: "Heap terpakai saat Encaps", u: "byte", w: "diukur di ESP32" } ] },',
              r'''      { k: "heap_encaps_used", l: "Heap terpakai saat Encaps", u: "byte", w: "diukur di ESP32" },
      { k: "net_energy_keygen_mj", l: "Energi bersih KeyGen", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_encaps_mj", l: "Energi bersih Encaps", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_decaps_mj", l: "Energi bersih Decaps", u: "mJ", w: "INA219 dikurangi daya idle" } ] },'''))
PAIRS.append(('      { k: "heap_sign_used", l: "Heap terpakai saat Sign", u: "byte", w: "diukur di ESP32" } ] }',
              r'''      { k: "heap_sign_used", l: "Heap terpakai saat Sign", u: "byte", w: "diukur di ESP32" },
      { k: "net_energy_keygen_mj", l: "Energi bersih KeyGen", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_sign_mj", l: "Energi bersih Sign", u: "mJ", w: "INA219 dikurangi daya idle" },
      { k: "net_energy_verify_mj", l: "Energi bersih Verify", u: "mJ", w: "INA219 dikurangi daya idle" } ] }'''))

# 11. tempat catatan energi
PAIRS.append(('  <div class="legend" id="legend"></div>\n',
              '  <div class="legend" id="legend"></div>\n  <div id="enote"></div>\n'))

# 12. catatan bila energi bersih <= 0
PAIRS.append(('  $("chart").innerHTML = barChart(T, m, log);\n', r'''  $("chart").innerHTML = barChart(T, m, log);
  const neg = m.k.indexOf("net_energy") === 0 ? T.pairs.flat().filter(n => M(n, m.k) && M(n, m.k).mean <= 0) : [];
  $("enote").innerHTML = neg.length ? `<p class="hint">Energi bersih &le; 0 pada: ${neg.join(", ")}. Operasi terlalu singkat untuk dibedakan dari daya idle; perbanyak pengulangan di firmware.</p>` : "";
'''))

# 13. kartu sumber energi
PAIRS.append(('[D.source, "sumber data"]]\n',
              '[D.source, "sumber data"],\n    [D.energy_demo ? "DEMO" : (Object.values(A).some(a => Object.keys(a.metrics).some(k => k.indexOf("net_energy") === 0)) ? "INA219" : "belum ada"), "data energi"]]\n'))

# 14. banner merah untuk energi demo
PAIRS.append(('  document.querySelectorAll(".tab").forEach(b => b.onclick = () => setTab(b.dataset.t));\n', r'''  if (D.energy_demo)
    $("banner").innerHTML += '<div class="banner" style="background:#fde2e2;color:#7a1212;border-color:#e5a3a3"><b>ENERGI DEMO (sintetis).</b> Kolom energi dibuat otomatis hanya untuk melihat bentuk tampilan. Bukan hasil pengukuran INA219.</div>';
  document.querySelectorAll(".tab").forEach(b => b.onclick = () => setTab(b.dataset.t));
'''))

for i, (old, new) in enumerate(PAIRS, 1):
    if old not in s:
        sys.exit(f"[GAGAL] bagian #{i} tidak ditemukan di {PATH}; file TIDAK diubah. Kirim pesan ini ke Claude.")
    s = s.replace(old, new, 1)
PATH.write_text(s)
print(f"[OK] {PATH} diperbarui ({len(PAIRS)} perubahan): energi bersih + --demo-energy")
