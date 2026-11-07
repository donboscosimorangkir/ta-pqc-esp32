import sys
from pathlib import Path


def patch(path, pairs):
    s = Path(path).read_text()
    for i, (old, new) in enumerate(pairs, 1):
        if old not in s:
            sys.exit(f"[GAGAL] {path}: bagian #{i} tidak ditemukan, file tidak diubah.")
        s = s.replace(old, new, 1)
    Path(path).write_text(s)
    print(f"[OK] {path} diperbarui ({len(pairs)} perubahan)")


# ---------------------------------------------------------------- analyze_results.py
patch(sys.argv[1] if len(sys.argv) > 1 else "analyze_results.py", [
    # 1. kompatibilitas data protokol lama (Encaps diukur di PC)
    ('''    if "operation_type" not in df.columns:
        df["operation_type"] = "kem"
    df["operation_type"] = df["operation_type"].fillna("kem")
    return df
''', '''    if "operation_type" not in df.columns:
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
    return df
'''),
    # 2. heap Encaps
    ('''                         "heap_decaps_used": ("heap_before_decaps", "heap_after_decaps"),
                         "heap_sign_used"''', '''                         "heap_decaps_used": ("heap_before_decaps", "heap_after_decaps"),
                         "heap_encaps_used": ("heap_before_encaps", "heap_after_encaps"),
                         "heap_sign_used"'''),
    # 3. kelompok KEM: Encaps kini diukur di ESP32
    ('("encaps_time_ms", "Encaps (server)")', '("encaps_time_ms", "Encaps")'),
    ('''        cpu=["keygen_time_ms", "decaps_time_ms"], wire=["pk_size_bytes", "ct_size_bytes"],''',
     '''        cpu=["keygen_time_ms", "encaps_time_ms", "decaps_time_ms"], wire=["pk_size_bytes", "ct_size_bytes"],
        extra=["server_encaps_time_ms"],'''),
    ('''        cmp=[("keygen_time_ms", "KeyGen"), ("decaps_time_ms", "Decaps"),
             ("pk_size_bytes", "ukuran public key"), ("ct_size_bytes", "ukuran ciphertext")]),''',
     '''        cmp=[("keygen_time_ms", "KeyGen"), ("encaps_time_ms", "Encaps"), ("decaps_time_ms", "Decaps"),
             ("pk_size_bytes", "ukuran public key"), ("ct_size_bytes", "ukuran ciphertext")]),'''),
    # 4. statistik juga memuat kolom pembanding (Encaps di server)
    ('''    cols = [c for c, _ in G["time"]] + ["network_rtt_ms"]
    rows = []''', '''    cols = [c for c, _ in G["time"]] + ["network_rtt_ms"] + G.get("extra", [])
    rows = []'''),
])

# ---------------------------------------------------------------- build_benchmark.py
patch(sys.argv[2] if len(sys.argv) > 2 else "build_benchmark.py", [
    ('''COLS = ["keygen_time_ms", "encaps_time_ms", "decaps_time_ms", "sign_time_ms",''',
     '''COLS = ["keygen_time_ms", "encaps_time_ms", "server_encaps_time_ms", "decaps_time_ms", "sign_time_ms",'''),
    ('''    "heap_decaps_used": ("heap_before_decaps", "heap_after_decaps"),
    "heap_sign_used"''', '''    "heap_decaps_used": ("heap_before_decaps", "heap_after_decaps"),
    "heap_encaps_used": ("heap_before_encaps", "heap_after_encaps"),
    "heap_sign_used"'''),
    ('''def build(rows):
    algos = {}
''', '''def normalize(rows):
    """Protokol lama (1 ronde): Encaps diukur di PC, bukan di ESP32."""
    for r in rows:
        if r.get("operation_type", "kem") == "kem" and (r.get("kem_rounds") or 1) < 2:
            if r.get("server_encaps_time_ms") is None:
                r["server_encaps_time_ms"] = r.get("encaps_time_ms")
            r["encaps_time_ms"] = None
    return rows


def build(rows):
    rows = normalize(rows)
    algos = {}
'''),
    ('''    cpu: ["keygen_time_ms", "decaps_time_ms"], size: ["pk_size_bytes", "ct_size_bytes"],
    cpuL: "KeyGen + Decaps", sizeL: "public key + ciphertext",''',
     '''    cpu: ["keygen_time_ms", "encaps_time_ms", "decaps_time_ms"], size: ["pk_size_bytes", "ct_size_bytes"],
    cpuL: "KeyGen + Encaps + Decaps", sizeL: "public key + ciphertext",'''),
    ('''      { k: "encaps_time_ms", l: "Waktu Encaps", u: "ms", w: "diukur di server PC" },''',
     '''      { k: "encaps_time_ms", l: "Waktu Encaps", u: "ms", w: "diukur di ESP32 (ronde 2)" },
      { k: "server_encaps_time_ms", l: "Waktu Encaps (server, pembanding)", u: "ms", w: "diukur di server PC" },'''),
    ('''      { k: "heap_decaps_used", l: "Heap terpakai saat Decaps", u: "byte", w: "diukur di ESP32" } ] },''',
     '''      { k: "heap_decaps_used", l: "Heap terpakai saat Decaps", u: "byte", w: "diukur di ESP32" },
      { k: "heap_encaps_used", l: "Heap terpakai saat Encaps", u: "byte", w: "diukur di ESP32" } ] },'''),
])
