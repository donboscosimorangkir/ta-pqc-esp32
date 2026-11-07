#!/usr/bin/env python3
"""Ringkasan statistik energi (INA219) dari results_energi_gabungan.db.
Hanya membaca database (mode ro). Menulis ringkasan_energi.csv dan .md."""
import csv
import os
import sqlite3
import statistics as st

DB = os.path.expanduser("~/ta-project/server/results_energi_gabungan.db")
OUT = os.path.expanduser("~/ta-project/analysis")

# (kolom energi, kolom waktu, label operasi)
OPS = [
    ("energy_keygen_mj", "keygen_time_ms", "KeyGen"),
    ("energy_encaps_mj", "encaps_time_ms", "Encaps"),
    ("energy_decaps_mj", "decaps_time_ms", "Decaps"),
    ("energy_sign_mj", "sign_time_ms", "Sign"),
    ("energy_verify_mj", "verify_time_ms", "Verify"),
]


def tren(xs):
    """Perubahan relatif rata-rata 3 trial terakhir terhadap 3 trial pertama (%)."""
    if len(xs) < 6:
        return None
    a, b = st.mean(xs[:3]), st.mean(xs[-3:])
    return (b - a) / a * 100.0 if a else None


con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
con.row_factory = sqlite3.Row
algos = [r[0] for r in con.execute(
    "select algorithm from trials group by algorithm order by min(id)")]

rows = []
for alg in algos:
    for ecol, tcol, label in OPS:
        data = con.execute(
            f"select {ecol} e, {tcol} t, idle_power_mw i from trials "
            f"where algorithm=? and status='success' and {ecol} is not null "
            f"order by id", (alg,)).fetchall()
        if not data:
            continue
        e = [d["e"] for d in data]
        t = [d["t"] for d in data if d["t"] is not None]
        idle = [d["i"] for d in data if d["i"] is not None]
        n = len(e)
        mean_e = st.mean(e)
        mean_t = st.mean(t) if t else None
        p_net = mean_e / mean_t * 1000.0 if mean_t else None
        tr = tren(e)
        rows.append({
            "algoritma": alg,
            "operasi": label,
            "n": n,
            "energi_rata2_mJ": round(mean_e, 2),
            "sd_mJ": round(st.stdev(e), 2) if n > 1 else "",
            "min_mJ": round(min(e), 2),
            "maks_mJ": round(max(e), 2),
            "waktu_rata2_ms": round(mean_t, 1) if mean_t else "",
            "daya_bersih_mW": round(p_net, 1) if p_net else "",
            "idle_rata2_mW": round(st.mean(idle), 1) if idle else "",
            "tren_awal_ke_akhir_persen": round(tr, 1) if tr is not None else "",
        })

os.makedirs(OUT, exist_ok=True)
csv_path = os.path.join(OUT, "ringkasan_energi.csv")
md_path = os.path.join(OUT, "ringkasan_energi.md")
heads = list(rows[0].keys())

with open(csv_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=heads)
    w.writeheader()
    w.writerows(rows)

with open(md_path, "w", encoding="utf-8") as f:
    f.write("| " + " | ".join(heads) + " |\n")
    f.write("|" + "---|" * len(heads) + "\n")
    for r in rows:
        f.write("| " + " | ".join(str(r[h]) for h in heads) + " |\n")

print(open(md_path, encoding="utf-8").read())
print("Disimpan:", csv_path, "dan", md_path)
