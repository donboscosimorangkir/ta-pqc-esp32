#!/usr/bin/env python3
"""
Analisis hasil pengujian PQC pada ESP32-WROOM-32.

Mencakup dua kelompok:
  - Key Establishment : ML-KEM vs HQC          (KeyGen, Encaps, Decaps)
  - Digital Signature : ML-DSA vs SLH-DSA      (KeyGen, Sign, Verify)

Metrik: waktu eksekusi, ukuran data, success rate, heap, dan energi (INA219).
Energi bersih = energi terukur - idle_power_mw * durasi operasi.

Keluaran (di --outdir): CSV statistik, grafik PNG per kelompok, dan LAPORAN_HASIL.html.

Jalankan:
    python analyze_results.py --db ../server/results.db --outdir ./analysis_output
Boleh beberapa database sekaligus (data digabung):
    python analyze_results.py --db a.db b.db --outdir ./analysis_output
Uji bentuk grafik energi sebelum sensor tersedia (data energi SINTETIS):
    python analyze_results.py --db ../server/results_sim.db --demo-energy
Requirement: pip install pandas matplotlib numpy
"""
import argparse
import base64
import datetime
import sqlite3
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # aman dipakai di WSL tanpa display
import matplotlib.pyplot as plt

COL_A, COL_B = "#1F5C4F", "#C2410C"
SHADES = ["#1F5C4F", "#5FA595", "#B7D7CE"]
plt.rcParams.update({
    "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.25, "axes.axisbelow": True,
    "figure.facecolor": "white",
})

ALIAS = {
    "SLH_DSA_PURE_SHAKE_128S": "SLH-DSA-SHAKE-128s",
    "SLH_DSA_PURE_SHAKE_192S": "SLH-DSA-SHAKE-192s",
    "SLH_DSA_PURE_SHAKE_256S": "SLH-DSA-SHAKE-256s",
}
ORDER = ["ML-KEM-512", "HQC-1", "ML-KEM-768", "HQC-3", "ML-KEM-1024", "HQC-5",
         "ML-DSA-44", "SLH-DSA-SHAKE-128s", "ML-DSA-65", "SLH-DSA-SHAKE-192s",
         "ML-DSA-87", "SLH-DSA-SHAKE-256s"]

# Kolom energi yang dikirim firmware (NULL jika INA219 tidak ada)
ENERGY_COLS_ALL = ["energy_keygen_mj", "energy_encaps_mj", "energy_decaps_mj",
                   "energy_sign_mj", "energy_verify_mj", "energy_samples_min",
                   "idle_power_mw", "ina_available"]

GROUPS = {
    "kem": dict(
        op="kem", label="Key Establishment (ML-KEM vs HQC)", fams=("ML-KEM", "HQC"),
        time=[("keygen_time_ms", "KeyGen"), ("encaps_time_ms", "Encaps"), ("decaps_time_ms", "Decaps")],
        size=[("pk_size_bytes", "Public key"), ("ct_size_bytes", "Ciphertext"), ("ss_size_bytes", "Shared secret")],
        heap="heap_after_decaps", logy=False,
        cpu=["keygen_time_ms", "encaps_time_ms", "decaps_time_ms"], wire=["pk_size_bytes", "ct_size_bytes"],
        extra=["server_encaps_time_ms"],
        energy=[("energy_keygen_mj", "keygen_time_ms", "KeyGen"),
                ("energy_encaps_mj", "encaps_time_ms", "Encaps"),
                ("energy_decaps_mj", "decaps_time_ms", "Decaps")],
        levels=["Level 1", "Level 3", "Level 5"],
        pairs=[("ML-KEM-512", "HQC-1"), ("ML-KEM-768", "HQC-3"), ("ML-KEM-1024", "HQC-5")],
        cmp=[("keygen_time_ms", "KeyGen"), ("encaps_time_ms", "Encaps"), ("decaps_time_ms", "Decaps"),
             ("pk_size_bytes", "ukuran public key"), ("ct_size_bytes", "ukuran ciphertext"),
             ("net_energy_keygen_mj", "energi bersih KeyGen"), ("net_energy_encaps_mj", "energi bersih Encaps"),
             ("net_energy_decaps_mj", "energi bersih Decaps")]),
    "sig": dict(
        op="sig", label="Digital Signature (ML-DSA vs SLH-DSA)", fams=("ML-DSA", "SLH-DSA"),
        time=[("keygen_time_ms", "KeyGen"), ("sign_time_ms", "Sign"), ("verify_time_ms", "Verify (ESP32)"),
              ("server_verify_time_ms", "Verify (server)")],
        size=[("pk_size_bytes", "Public key"), ("sig_size_bytes", "Signature")],
        heap="heap_after_sign", logy=True,
        cpu=["keygen_time_ms", "sign_time_ms", "verify_time_ms"], wire=["pk_size_bytes", "sig_size_bytes"],
        energy=[("energy_keygen_mj", "keygen_time_ms", "KeyGen"),
                ("energy_sign_mj", "sign_time_ms", "Sign"),
                ("energy_verify_mj", "verify_time_ms", "Verify")],
        levels=["44 ↔ 128s", "65 ↔ 192s", "87 ↔ 256s"],
        pairs=[("ML-DSA-44", "SLH-DSA-SHAKE-128s"), ("ML-DSA-65", "SLH-DSA-SHAKE-192s"),
               ("ML-DSA-87", "SLH-DSA-SHAKE-256s")],
        cmp=[("keygen_time_ms", "KeyGen"), ("sign_time_ms", "Sign"), ("verify_time_ms", "Verify"),
             ("sig_size_bytes", "ukuran signature"),
             ("net_energy_keygen_mj", "energi bersih KeyGen"), ("net_energy_sign_mj", "energi bersih Sign"),
             ("net_energy_verify_mj", "energi bersih Verify")]),
}


# ---------------------------------------------------------------------------
# Util
# ---------------------------------------------------------------------------
def family_of(name):
    for f in ("ML-KEM", "HQC", "ML-DSA", "SLH-DSA"):
        if str(name).startswith(f):
            return f
    return "?"


def order_algos(names):
    names = list(dict.fromkeys(names))
    return sorted(names, key=lambda a: (ORDER.index(a) if a in ORDER else 99, a))


def fam_color(algo, G):
    return COL_A if family_of(algo) == G["fams"][0] else COL_B


def has(df, col):
    return col in df.columns and df[col].notna().any()


def load_data(paths):
    frames = []
    for p in paths:
        if not Path(p).exists():
            sys.exit(f"Error: file database tidak ditemukan: {p}")
        conn = sqlite3.connect(p)
        frames.append(pd.read_sql_query("SELECT * FROM trials", conn))
        conn.close()
    df = pd.concat(frames, ignore_index=True)
    if df.empty:
        sys.exit("Error: tabel 'trials' kosong, belum ada data pengujian.")
    df["algorithm"] = df["algorithm"].replace(ALIAS)
    df["algorithm_family"] = df["algorithm"].map(family_of)
    df["security_category"] = pd.to_numeric(df["security_category"], errors="coerce")
    if "operation_type" not in df.columns:
        df["operation_type"] = "kem"
    df["operation_type"] = df["operation_type"].fillna("kem")
    # Protokol lama (1 ronde): Encaps diukur di PC, bukan di ESP32.
    for c in ("kem_rounds", "server_encaps_time_ms"):
        if c not in df.columns:
            df[c] = np.nan
    old = (df["operation_type"] == "kem") & (df["kem_rounds"].fillna(1) < 2)
    m = old & df["server_encaps_time_ms"].isna()
    df.loc[m, "server_encaps_time_ms"] = df.loc[m, "encaps_time_ms"]
    df.loc[old, "encaps_time_ms"] = np.nan
    # Database lama belum punya kolom energi: isi NaN supaya analisis tetap jalan.
    for c in ENERGY_COLS_ALL:
        if c not in df.columns:
            df[c] = np.nan
    return df


def heap_delta(df):
    """Tambah kolom heap_*_used (sebelum - sesudah) bila datanya ada (dari ESP32)."""
    for name, (b, a) in {"heap_keygen_used": ("heap_before_keygen", "heap_after_keygen"),
                         "heap_decaps_used": ("heap_before_decaps", "heap_after_decaps"),
                         "heap_encaps_used": ("heap_before_encaps", "heap_after_encaps"),
                         "heap_sign_used": ("heap_before_sign", "heap_after_sign")}.items():
        if b in df.columns and a in df.columns:
            df[name] = df[b] - df[a]
    return df


def energy_net(df):
    """Energi bersih (mJ) = energi terukur - idle_power_mw * durasi operasi / 1000.
    mW x detik = mJ. Kolom baru diberi awalan 'net_'."""
    for G in GROUPS.values():
        for e, t, _ in G["energy"]:
            n = f"net_{e}"
            if n not in df.columns and t in df.columns:
                df[n] = df[e]  # nilai tersimpan sudah energi bersih (idle dikurangi di firmware)
    return df


def inject_demo_energy(df, seed=42):
    """DATA SINTETIS: hanya untuk melihat bentuk grafik energi sebelum sensor tersedia."""
    rng = np.random.default_rng(seed)
    n = len(df)
    tmap = {"energy_keygen_mj": "keygen_time_ms", "energy_encaps_mj": "encaps_time_ms",
            "energy_decaps_mj": "decaps_time_ms", "energy_sign_mj": "sign_time_ms",
            "energy_verify_mj": "verify_time_ms"}
    idle = rng.normal(450.0, 15.0, n)      # mW, kira-kira ESP32 + WiFi idle
    extra = rng.normal(180.0, 10.0, n)     # mW tambahan saat komputasi
    df["idle_power_mw"] = idle
    df["ina_available"] = 1
    for e, t in tmap.items():
        df[e] = (idle + extra) * df[t] / 1000.0
    df["energy_samples_min"] = df[list(tmap.values())].min(axis=1).round().clip(lower=0)  # ~1 sampel/ms
    return df


# ---------------------------------------------------------------------------
# Statistik
# ---------------------------------------------------------------------------
def descriptive_stats(ok, G):
    cols = [c for c, _ in G["time"]] + ["network_rtt_ms"] + G.get("extra", [])
    rows = []
    for algo, g in ok.groupby("algorithm"):
        row = {"algorithm": algo, "n_trials": len(g)}
        for c in cols:
            if has(g, c):
                s = g[c].dropna()
                row.update({f"{c}_mean": s.mean(), f"{c}_median": s.median(), f"{c}_min": s.min(),
                            f"{c}_max": s.max(), f"{c}_std": s.std()})
        rows.append(row)
    d = pd.DataFrame(rows).set_index("algorithm")
    return d.reindex(order_algos(d.index))


def size_summary(ok, G):
    cols = [c for c, _ in G["size"] if has(ok, c)]
    d = ok.groupby("algorithm")[cols].mean()
    return d.reindex(order_algos(d.index))


def success_summary(df):
    # hitung per trial_id (bukan per baris): satu trial bisa punya beberapa baris percobaan (retry)
    t = df.assign(_ok=(df["status"] == "success")).groupby(["algorithm", "trial_id"])["_ok"].any().reset_index()
    s = t.groupby("algorithm").agg(total_trials=("_ok", "count"), success_count=("_ok", "sum"))
    s["success_rate_pct"] = (s["success_count"] / s["total_trials"] * 100).round(2)
    return s.reindex(order_algos(s.index))


def fail_breakdown(df):
    f = df[df["status"] != "success"]
    if f.empty or "fail_reason" not in f.columns:
        return None
    return f.groupby(["algorithm", "fail_reason"]).size()


def detect_leak(ok, col):
    res = {}
    if not has(ok, col):
        return res
    for a, g in ok.groupby("algorithm"):
        g = g.sort_values("trial_id").dropna(subset=[col])
        if len(g) < 3:
            continue
        slope = np.polyfit(g["trial_id"].values.astype(float), g[col].values.astype(float), 1)[0]
        res[a] = {"slope": round(float(slope), 3),
                  "indikasi": "Penurunan free heap (perlu diperiksa)" if slope < -50 else "Stabil"}
    return res


def has_energy(ok, G):
    return any(has(ok, f"net_{e}") for e, _, _ in G["energy"])


def energy_stats(ok, G):
    rows = []
    for algo, g in ok.groupby("algorithm"):
        row = {"algorithm": algo, "n_trials": len(g)}
        for e, _, _ in G["energy"]:
            n = f"net_{e}"
            if has(g, n):
                s = g[n].dropna()
                row[f"{n}_mean"] = s.mean()
                row[f"{n}_std"] = s.std()
                row[f"{e}_mean"] = g[e].dropna().mean()
        if has(g, "energy_samples_min"):
            row["samples_min_mean"] = g["energy_samples_min"].dropna().mean()
        if has(g, "idle_power_mw"):
            row["idle_power_mw_mean"] = g["idle_power_mw"].dropna().mean()
        rows.append(row)
    d = pd.DataFrame(rows).set_index("algorithm")
    return d.reindex(order_algos(d.index))


# ---------------------------------------------------------------------------
# Gambar (fungsi draw_* dipakai ulang oleh grafik tunggal dan dashboard)
# ---------------------------------------------------------------------------
def style_x(ax, algos):
    ax.set_xticks(range(len(algos)))
    ax.set_xticklabels([a.replace("SLH-DSA-SHAKE-", "SLH-") for a in algos], rotation=45, ha="right")


def draw_time(ax, ok, G, col, label):
    algos = [a for a in order_algos(ok["algorithm"].unique()) if has(ok[ok["algorithm"] == a], col)]
    means = [ok.loc[ok["algorithm"] == a, col].mean() for a in algos]
    stds = [np.nan_to_num(ok.loc[ok["algorithm"] == a, col].std()) for a in algos]
    ax.bar(range(len(algos)), means, yerr=stds, capsize=3, color=[fam_color(a, G) for a in algos], alpha=0.9)
    if G["logy"]:
        ax.set_yscale("log")
    style_x(ax, algos)
    ax.set_title(label)
    ax.set_ylabel("ms" + (" (skala log)" if G["logy"] else ""))


def draw_energy(ax, ok, G, col, label):
    algos = [a for a in order_algos(ok["algorithm"].unique()) if has(ok[ok["algorithm"] == a], col)]
    means = [ok.loc[ok["algorithm"] == a, col].mean() for a in algos]
    stds = [np.nan_to_num(ok.loc[ok["algorithm"] == a, col].std()) for a in algos]
    ax.bar(range(len(algos)), means, yerr=stds, capsize=3, color=[fam_color(a, G) for a in algos], alpha=0.9)
    if G["logy"]:
        ax.set_yscale("log")
    style_x(ax, algos)
    ax.set_title(label)
    ax.set_ylabel("mJ, energi bersih" + (" (skala log)" if G["logy"] else ""))


def draw_sizes(ax, ok, G):
    sz = size_summary(ok, G)
    labels = {c: l for c, l in G["size"]}
    w = 0.8 / max(len(sz.columns), 1)
    for i, c in enumerate(sz.columns):
        ax.bar(np.arange(len(sz)) + i * w, sz[c].values, w, label=labels[c], color=SHADES[i % 3])
    ax.set_xticks(np.arange(len(sz)) + w * (len(sz.columns) - 1) / 2)
    ax.set_xticklabels([a.replace("SLH-DSA-SHAKE-", "SLH-") for a in sz.index], rotation=45, ha="right")
    if G["logy"]:
        ax.set_yscale("log")
    ax.set_ylabel("byte" + (" (skala log)" if G["logy"] else ""))
    ax.legend(fontsize=8)
    ax.set_title("Ukuran data")


def draw_success(ax, df, G):
    s = success_summary(df)
    ax.bar(range(len(s)), s["success_rate_pct"].values, color=[fam_color(a, G) for a in s.index])
    ax.axhline(100, color="gray", ls="--", alpha=0.5)
    ax.set_ylim(0, 108)
    style_x(ax, list(s.index))
    ax.set_ylabel("%")
    ax.set_title("Success rate")


def draw_tradeoff(ax, ok, G):
    pts = []
    for a in order_algos(ok["algorithm"].unique()):
        g = ok[ok["algorithm"] == a]
        if all(has(g, c) for c in G["cpu"] + G["wire"]):
            pts.append((a, sum(g[c].mean() for c in G["wire"]), sum(g[c].mean() for c in G["cpu"])))
    for a, x, y in pts:
        ax.scatter(x, y, s=70, color=fam_color(a, G), alpha=0.9, zorder=3)
        ax.annotate(a.replace("SLH-DSA-SHAKE-", "SLH-"), (x, y), textcoords="offset points", xytext=(7, 5), fontsize=8)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("data dikirim lewat jaringan (byte)")
    ax.set_ylabel("waktu komputasi ESP32 (ms)")
    ax.set_title("Trade-off waktu vs ukuran data")
    return bool(pts)


def save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_time(ok, G, out, key):
    cols = [(c, l) for c, l in G["time"] if has(ok, c)]
    fig, axes = plt.subplots(1, len(cols), figsize=(4.6 * len(cols), 5), squeeze=False)
    for ax, (c, l) in zip(axes[0], cols):
        draw_time(ax, ok, G, c, l)
    fig.suptitle(f"Rata-rata waktu eksekusi per algoritma - {G['label']}", fontweight="bold")
    save(fig, out / f"{key}_01_waktu.png")


def plot_trend(ok, G, out, key):
    cols = [(c, l) for c, l in G["time"] if has(ok, c)]
    fig, axes = plt.subplots(1, len(cols), figsize=(4.6 * len(cols), 4.5), squeeze=False)
    for ax, (c, l) in zip(axes[0], cols):
        for i, f in enumerate(G["fams"]):
            g = ok[ok["algorithm_family"] == f].groupby("security_category")[c].mean().dropna().sort_index()
            if len(g):
                ax.plot(g.index, g.values, marker="o", lw=2, label=f, color=COL_A if i == 0 else COL_B)
        if G["logy"]:
            ax.set_yscale("log")
        ax.set_xticks(sorted(ok["security_category"].dropna().unique()))
        ax.set_xlabel("NIST Security Category")
        ax.set_ylabel("ms")
        ax.set_title(l)
        ax.legend(fontsize=8)
    fig.suptitle(f"Tren waktu terhadap security category - {G['label']}", fontweight="bold")
    save(fig, out / f"{key}_02_tren_kategori.png")


def plot_box(ok, G, out, key):
    cols = [(c, l) for c, l in G["time"] if has(ok, c)]
    fig, axes = plt.subplots(1, len(cols), figsize=(4.6 * len(cols), 5), squeeze=False)
    for ax, (c, l) in zip(axes[0], cols):
        algos = [a for a in order_algos(ok["algorithm"].unique()) if has(ok[ok["algorithm"] == a], c)]
        data = [ok.loc[ok["algorithm"] == a, c].dropna().values for a in algos]
        bp = ax.boxplot(data, patch_artist=True)
        for patch, a in zip(bp["boxes"], algos):
            patch.set_facecolor(fam_color(a, G))
            patch.set_alpha(0.75)
        for med in bp["medians"]:
            med.set_color("black")
        if G["logy"]:
            ax.set_yscale("log")
        ax.set_xticks(range(1, len(algos) + 1))
        ax.set_xticklabels([a.replace("SLH-DSA-SHAKE-", "SLH-") for a in algos], rotation=45, ha="right")
        ax.set_title(l)
        ax.set_ylabel("ms")
    fig.suptitle(f"Sebaran (variabilitas) waktu eksekusi - {G['label']}", fontweight="bold")
    save(fig, out / f"{key}_03_sebaran.png")


def plot_sizes(ok, G, out, key):
    fig, ax = plt.subplots(figsize=(9, 5))
    draw_sizes(ax, ok, G)
    save(fig, out / f"{key}_04_ukuran_data.png")


def plot_success(df, G, out, key):
    fig, ax = plt.subplots(figsize=(8, 4.5))
    draw_success(ax, df, G)
    save(fig, out / f"{key}_05_success_rate.png")


def plot_heap(ok, G, out, key):
    col = G["heap"]
    if not has(ok, col):
        return False
    fig, ax = plt.subplots(figsize=(10, 5))
    for a in order_algos(ok["algorithm"].unique()):
        g = ok[ok["algorithm"] == a].sort_values("trial_id").dropna(subset=[col])
        if len(g):
            ax.plot(g["trial_id"], g[col], marker=".", alpha=0.85, label=a)
    ax.set_xlabel("Trial ke-")
    ax.set_ylabel("Free heap (byte)")
    ax.set_title(f"Tren free heap sepanjang trial (deteksi memory leak) - {G['label']}")
    ax.legend(fontsize=7, ncol=2)
    save(fig, out / f"{key}_06_tren_heap.png")
    return True


def plot_tradeoff(ok, G, out, key):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    ok_pts = draw_tradeoff(ax, ok, G)
    if not ok_pts:
        plt.close(fig)
        return False
    save(fig, out / f"{key}_07_tradeoff.png")
    return True


def plot_energy(ok, G, out, key, demo=False):
    cols = [(f"net_{e}", lab) for e, _, lab in G["energy"] if has(ok, f"net_{e}")]
    if not cols:
        return False
    fig, axes = plt.subplots(1, len(cols), figsize=(4.6 * len(cols), 5), squeeze=False)
    for ax, (c, l) in zip(axes[0], cols):
        draw_energy(ax, ok, G, c, l)
    title = f"Energi bersih per operasi - {G['label']}"
    if demo:
        title += "  [DATA DEMO SINTETIS]"
    fig.suptitle(title, fontweight="bold")
    save(fig, out / f"{key}_08_energi.png")
    return True


def plot_dashboard(df, ok, G, out, key):
    cols = [(c, l) for c, l in G["time"] if has(ok, c)][:3]
    fig = plt.figure(figsize=(16, 10))
    fig.suptitle(f"Ringkasan Hasil Pengujian: {G['label']}", fontsize=16, fontweight="bold")
    for i, (c, l) in enumerate(cols):
        draw_time(fig.add_subplot(2, 3, i + 1), ok, G, c, l)
    draw_sizes(fig.add_subplot(2, 3, 4), ok, G)
    draw_success(fig.add_subplot(2, 3, 5), df, G)
    draw_tradeoff(fig.add_subplot(2, 3, 6), ok, G)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(out / f"{key}_00_dashboard.png", dpi=150)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Narasi otomatis
# ---------------------------------------------------------------------------
def narrative(ok, G, source_is_sim):
    items = []
    algos = set(ok["algorithm"])
    for lvl, (a, b) in zip(G["levels"], G["pairs"]):
        if a not in algos or b not in algos:
            continue
        parts = []
        for col, lab in G["cmp"]:
            if col not in ok.columns:
                continue
            va, vb = ok.loc[ok["algorithm"] == a, col].mean(), ok.loc[ok["algorithm"] == b, col].mean()
            if pd.isna(va) or pd.isna(vb) or va <= 0 or vb <= 0:
                continue
            r = vb / va
            if r >= 1.05:
                parts.append(f"{lab}: {b} {r:.1f}x lebih tinggi")
            elif r <= 1 / 1.05:
                parts.append(f"{lab}: {b} {1 / r:.1f}x lebih rendah")
            else:
                parts.append(f"{lab}: setara")
        if parts:
            items.append(f"<b>{lvl}</b> ({a} vs {b}) &mdash; " + "; ".join(parts) + ".")
    if G["op"] == "sig":
        items.append("Catatan pemasangan: ML-DSA-44 mengklaim kategori NIST 2, sedangkan SLH-DSA-128s kategori 1; "
                     "pasangan dibuat per tingkat (44-128s, 65-192s, 87-256s), bukan kategori yang identik.")
    if source_is_sim:
        items.append("Data berasal dari simulasi PC, sehingga waktu eksekusi jauh lebih cepat dari ESP32 dan "
                     "tidak dapat dipakai sebagai hasil akhir.")
    return items


# ---------------------------------------------------------------------------
# Laporan HTML
# ---------------------------------------------------------------------------
CSS = """
body{font-family:Georgia,'Times New Roman',serif;max-width:920px;margin:40px auto;padding:0 22px;line-height:1.65;color:#1d2421}
h1{font-size:28px;margin-bottom:6px}
h2{font-size:21px;color:#1F5C4F;margin-top:44px;border-bottom:1px solid #1F5C4F;padding-bottom:4px}
h3{font-size:16px;margin:26px 0 6px}
.meta{border-left:3px solid #1F5C4F;padding:2px 16px;margin:14px 0}
blockquote{border-left:3px solid #1F5C4F;margin:12px 0;padding:2px 16px;background:#f5f8f6}
blockquote li{margin:6px 0}
table.t{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
table.t th,table.t td{border-bottom:1px solid #d8d8d0;padding:6px 8px;text-align:right;font-family:Consolas,'Courier New',monospace}
table.t th{font-family:Georgia,serif;font-weight:bold;color:#444;border-bottom:1.5px solid #1F5C4F}
table.t td:first-child,table.t th:first-child{text-align:left}
.sc{overflow-x:auto}
figure{margin:22px 0;text-align:center}
figure img{max-width:100%;border:1px solid #e0e0d8}
figcaption{font-size:13px;color:#555;margin-top:6px;font-style:italic}
"""


def img64(path):
    return base64.b64encode(path.read_bytes()).decode() if path.exists() else ""


def tbl(d, nd=3):
    return '<div class="sc">' + d.round(nd).to_html(classes="t", border=0) + "</div>"


def group_section(key, G, df, ok, stats, sizes, succ, leaks, outdir, extras):
    h = [f"<h2>{G['label']}</h2>"]
    h.append("<h3>Ringkasan temuan</h3><blockquote><ul>")
    h += [f"<li>{x}</li>" for x in narrative(ok, G, extras["sim"])]
    for a, r in succ.iterrows():
        rate = r["success_rate_pct"]
        h.append(f"<li>{a}: success rate {rate}% ({int(r['success_count'])}/{int(r['total_trials'])})"
                 f"{'' if rate >= 100 else ' &mdash; perlu dicek penyebab kegagalan'}.</li>")
    h.append("</ul></blockquote>")
    h.append("<h3>Statistik deskriptif waktu eksekusi (ms)</h3>")
    h.append("<p>Dihitung dari trial berstatus sukses.</p>" + tbl(stats))
    h.append("<h3>Ukuran data (byte)</h3>" + tbl(sizes, 1))
    h.append("<h3>Success rate</h3>" + tbl(succ, 2))
    h.append("<h3>Deteksi memory leak</h3>")
    if leaks:
        rows = "".join(f"<tr><td>{a}</td><td>{r['slope']}</td><td>{r['indikasi']}</td></tr>" for a, r in leaks.items())
        h.append("<p>Slope regresi linear free heap terhadap trial; mendekati 0 berarti stabil.</p>"
                 f'<table class="t"><tr><th>Algoritma</th><th>Slope (byte/trial)</th><th>Indikasi</th></tr>{rows}</table>')
    else:
        h.append("<p>Data heap belum tersedia (data simulasi PC, bukan dari ESP32).</p>")

    est = extras.get("estats")
    h.append("<h3>Energi per operasi (mJ)</h3>")
    if est is not None:
        note = ("Energi bersih = energi terukur INA219 dikurangi daya idle x durasi operasi (pengurangan dilakukan di firmware, nilai tersimpan sudah bersih). "
                "Nilai dapat mendekati nol atau negatif pada operasi yang sangat singkat karena derau pengukuran. "
                "Pengukuran mencakup daya seluruh board (5 V), bukan hanya CPU.")
        if extras.get("energy_demo"):
            note = ("<b>DATA ENERGI DEMO (sintetis, dibuat otomatis). Hanya untuk menguji bentuk grafik, "
                    "bukan hasil pengukuran.</b> " + note)
        h.append(f"<p>{note}</p>")
        if "samples_min_mean" in est.columns:
            low = est.index[est["samples_min_mean"] < 5].tolist()
            if low:
                h.append("<p>Peringatan: rata-rata sampel INA219 per operasi kurang dari 5 untuk "
                         + ", ".join(low) + ", sehingga energi operasi singkat kurang andal; "
                         "pertimbangkan mengulang operasi dalam satu jendela ukur.</p>")
        h.append(tbl(est, 4))
    else:
        h.append("<p>Data energi belum tersedia (INA219 belum dipakai pada data ini).</p>")

    caps = [("00_dashboard", "Ringkasan seluruh metrik dalam satu tampilan."),
            ("01_waktu", "Rata-rata waktu eksekusi per tahap; garis hitam = simpangan baku."),
            ("02_tren_kategori", "Tren waktu terhadap NIST security category."),
            ("03_sebaran", "Sebaran waktu eksekusi: konsistensi, bukan hanya rata-rata."),
            ("04_ukuran_data", "Perbandingan ukuran public key dan ciphertext/signature."),
            ("05_success_rate", "Tingkat keberhasilan tiap algoritma."),
            ("06_tren_heap", "Tren free heap sepanjang trial untuk deteksi memory leak."),
            ("07_tradeoff", "Trade-off antara waktu komputasi di ESP32 dan data yang dikirim."),
            ("08_energi", "Energi bersih per operasi (energi terukur dikurangi baseline idle).")]
    h.append("<h3>Grafik</h3>")
    for suffix, cap in caps:
        b = img64(outdir / f"{key}_{suffix}.png")
        if b:
            h.append(f'<figure><img src="data:image/png;base64,{b}" alt="{suffix}"><figcaption>{cap}</figcaption></figure>')
    return "\n".join(h)


def build_report(sections, df, outdir, sim, demo=False):
    algos = order_algos(df["algorithm"].unique())
    per = df.groupby("algorithm")["trial_id"].nunique().to_dict()
    if demo:
        energy_src = "DEMO sintetis (bukan hasil pengukuran)"
    elif has(df, "ina_available") and (df["ina_available"] == 1).any():
        energy_src = "INA219"
    else:
        energy_src = "belum ada"
    meta = (f"<div class='meta'><b>Algoritma diuji:</b> {', '.join(algos)}<br>"
            f"<b>Jumlah trial:</b> {', '.join(f'{a}: {per[a]}' for a in algos)}<br>"
            f"<b>Total data:</b> {len(df)} baris<br>"
            f"<b>Sumber data:</b> {'simulasi PC (bukan ESP32)' if sim else 'ESP32-WROOM-32'}<br>"
            f"<b>Data energi:</b> {energy_src}<br>"
            f"<b>Dibuat:</b> {datetime.datetime.now().strftime('%d %b %Y %H:%M')}</div>")
    html = (f"<!DOCTYPE html><html lang='id'><head><meta charset='utf-8'>"
            f"<title>Laporan Hasil Pengujian PQC pada ESP32-WROOM-32</title><style>{CSS}</style></head><body>"
            f"<h1>Laporan Hasil Pengujian PQC pada ESP32-WROOM-32</h1>"
            f"<h2>1. Parameter pengujian</h2>{meta}" + "\n".join(sections) + "</body></html>")
    p = outdir / "LAPORAN_HASIL.html"
    p.write_text(html, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Analisis hasil pengujian PQC (KEM + Signature)")
    ap.add_argument("--db", nargs="+", default=["../server/results.db"], help="satu atau beberapa file results.db")
    ap.add_argument("--outdir", default="./analysis_output")
    ap.add_argument("--demo-energy", action="store_true",
                    help="isi kolom energi dengan data SINTETIS untuk menguji grafik (bukan hasil pengukuran)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    df = heap_delta(load_data(args.db))
    if args.demo_energy:
        df = inject_demo_energy(df)
        print("!! PERINGATAN: --demo-energy aktif. Kolom energi SINTETIS, bukan hasil pengukuran. !!")
    df = energy_net(df)
    sim = not any(has(df, c) for c in ("heap_before_keygen", "heap_after_keygen"))
    print(f"Total {len(df)} baris data dimuat dari {len(args.db)} database.")
    pd.set_option("display.width", 170)
    pd.set_option("display.max_columns", None)

    sections, n_sec = [], 2
    for key, G in GROUPS.items():
        gdf = df[df["operation_type"] == G["op"]].copy()
        if gdf.empty:
            print(f"\n[lewati] Tidak ada data untuk {G['label']}")
            continue
        ok = gdf[gdf["status"] == "success"].copy()
        print("\n" + "=" * 78 + f"\n{G['label'].upper()}\n" + "=" * 78)

        stats = descriptive_stats(ok, G)
        sizes = size_summary(ok, G)
        succ = success_summary(gdf)
        leaks = detect_leak(ok, G["heap"])
        print("\n--- Statistik deskriptif (hanya trial sukses) ---")
        print(stats.round(4))
        print("\n--- Ukuran data rata-rata (byte) ---")
        print(sizes.round(1))
        print("\n--- Success rate ---")
        print(succ)
        fb = fail_breakdown(gdf)
        print("\n--- Breakdown penyebab kegagalan ---")
        print(fb if fb is not None else "(tidak ada kegagalan tercatat)")
        print("\n--- Deteksi memory leak ---")
        for a, r in leaks.items():
            print(f"  {a}: slope={r['slope']} byte/trial -> {r['indikasi']}")
        if not leaks:
            print("  (data heap belum tersedia)")

        estats = None
        if has_energy(ok, G):
            estats = energy_stats(ok, G)
            print("\n--- Energi per operasi (mJ, energi bersih) ---")
            print(estats.round(4))
            estats.to_csv(outdir / f"{key}_energi.csv")
        else:
            print("\n--- Energi per operasi ---\n  (data energi belum tersedia)")

        stats.to_csv(outdir / f"{key}_statistik_deskriptif.csv")
        sizes.to_csv(outdir / f"{key}_ukuran_data.csv")
        succ.to_csv(outdir / f"{key}_success_rate.csv")

        plot_dashboard(gdf, ok, G, outdir, key)
        plot_time(ok, G, outdir, key)
        plot_trend(ok, G, outdir, key)
        plot_box(ok, G, outdir, key)
        plot_sizes(ok, G, outdir, key)
        plot_success(gdf, G, outdir, key)
        plot_heap(ok, G, outdir, key)
        plot_tradeoff(ok, G, outdir, key)
        plot_energy(ok, G, outdir, key, demo=args.demo_energy)

        sec = group_section(key, G, gdf, ok, stats, sizes, succ, leaks, outdir,
                            {"sim": sim, "estats": estats, "energy_demo": args.demo_energy})
        sections.append(sec.replace("<h2>", f"<h2>{n_sec}. ", 1))
        n_sec += 1

    p = build_report(sections, df, outdir, sim, demo=args.demo_energy)
    print(f"\nSelesai. Grafik (.png), tabel (.csv), dan laporan tersimpan di: {outdir.resolve()}")
    print(f"Laporan HTML: {p.resolve()}")


if __name__ == "__main__":
    main()
