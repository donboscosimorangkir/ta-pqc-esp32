-- Skema database hasil pengujian PQC (Key Establishment + Digital Signature)
-- pada ESP32-WROOM-32. 1 baris = 1 trial.
--   operation_type = 'kem' : Ronde 1 (ESP32: KeyGen -> Decaps; server: Encaps)
--                            Ronde 2 (peran ditukar; server: KeyGen -> Decaps; ESP32: Encaps)
--                            => KeyGen, Encaps, Decaps seluruhnya terukur di ESP32 (kem_rounds = 2)
--   operation_type = 'sig' : KeyGen -> Sign -> Verify (semua di ESP32)

CREATE TABLE IF NOT EXISTS trials (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_id                INTEGER NOT NULL,
    algorithm               TEXT NOT NULL,          -- e.g. 'ML-KEM-512', 'HQC-1', 'ML-DSA-44'
    algorithm_family        TEXT NOT NULL,          -- 'ML-KEM' | 'HQC' | 'ML-DSA' | 'SLH-DSA'
    operation_type          TEXT NOT NULL DEFAULT 'kem',  -- 'kem' | 'sig'
    security_category       INTEGER NOT NULL,       -- level NIST yang diklaim (1..5)
    timestamp               TEXT NOT NULL,          -- ISO 8601

    -- Waktu eksekusi (ms)
    keygen_time_ms          REAL,                   -- ESP32
    decaps_time_ms          REAL,                   -- ESP32
    encaps_time_ms          REAL,                   -- ESP32 (ronde 2); protokol lama (kem_rounds=1): PC
    server_encaps_time_ms   REAL,                   -- PC (ronde 1), hanya sebagai pembanding
    sign_time_ms            REAL,                   -- ESP32
    verify_time_ms          REAL,                   -- ESP32 (verify lokal)
    server_verify_time_ms   REAL,                   -- PC (verify independen)
    network_rtt_ms          REAL,

    -- Heap memori (bytes, dari ESP32)
    heap_before_keygen      INTEGER,
    heap_after_keygen       INTEGER,
    heap_before_decaps      INTEGER,
    heap_after_decaps       INTEGER,
    heap_before_encaps      INTEGER,
    heap_after_encaps       INTEGER,
    heap_before_sign        INTEGER,
    heap_after_sign         INTEGER,
    heap_min_during_cycle   INTEGER,

    -- Energi (mJ) per operasi dari INA219; NULL jika sensor tidak ada.
    -- Energi bersih = energy - idle_power_mw * durasi operasi.
    energy_keygen_mj        REAL,
    energy_encaps_mj        REAL,
    energy_decaps_mj        REAL,
    energy_sign_mj          REAL,
    energy_verify_mj        REAL,
    energy_samples_min      INTEGER,                -- sampel terkecil di antara operasi (makin kecil makin tidak andal)
    idle_power_mw           REAL,                   -- baseline daya idle untuk konfigurasi ini
    ina_available           INTEGER,                -- 1 = sensor terbaca

    -- Ukuran data (bytes)
    pk_size_bytes           INTEGER,
    ct_size_bytes           INTEGER,
    ss_size_bytes           INTEGER,
    sig_size_bytes          INTEGER,

    -- Status
    status                  TEXT NOT NULL,          -- 'success' | 'fail'
    fail_reason             TEXT,                   -- NULL jika sukses
    retry_count             INTEGER DEFAULT 0,
    kem_rounds              INTEGER,                -- 2 = ESP32 mengerjakan ketiga operasi KEM

    -- Metadata koneksi
    client_ip               TEXT
);

CREATE INDEX IF NOT EXISTS idx_algorithm ON trials(algorithm);
CREATE INDEX IF NOT EXISTS idx_status ON trials(status);
CREATE INDEX IF NOT EXISTS idx_trial_id ON trials(trial_id, algorithm);

-- Ringkasan KEM
CREATE VIEW IF NOT EXISTS summary_per_algorithm AS
SELECT
    algorithm,
    algorithm_family,
    security_category,
    COUNT(*) AS total_trials,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_count,
    ROUND(100.0 * SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) / COUNT(*), 2) AS success_rate_pct,
    ROUND(AVG(keygen_time_ms), 3) AS avg_keygen_ms,
    ROUND(AVG(encaps_time_ms), 3) AS avg_encaps_ms,
    ROUND(AVG(decaps_time_ms), 3) AS avg_decaps_ms,
    ROUND(AVG(heap_after_keygen - heap_before_keygen), 1) AS avg_heap_delta_keygen,
    ROUND(AVG(heap_after_decaps - heap_before_decaps), 1) AS avg_heap_delta_decaps,
    ROUND(AVG(energy_keygen_mj), 4) AS avg_energy_keygen_mj,
    ROUND(AVG(energy_encaps_mj), 4) AS avg_energy_encaps_mj,
    ROUND(AVG(energy_decaps_mj), 4) AS avg_energy_decaps_mj,
    AVG(pk_size_bytes) AS avg_pk_size,
    AVG(ct_size_bytes) AS avg_ct_size
FROM trials
WHERE operation_type = 'kem'
GROUP BY algorithm;

-- Ringkasan Digital Signature
CREATE VIEW IF NOT EXISTS summary_signature AS
SELECT
    algorithm,
    algorithm_family,
    security_category,
    COUNT(*) AS total_trials,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_count,
    ROUND(100.0 * SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) / COUNT(*), 2) AS success_rate_pct,
    ROUND(AVG(keygen_time_ms), 3) AS avg_keygen_ms,
    ROUND(AVG(sign_time_ms), 3) AS avg_sign_ms,
    ROUND(AVG(verify_time_ms), 3) AS avg_verify_ms,
    ROUND(AVG(server_verify_time_ms), 3) AS avg_server_verify_ms,
    ROUND(AVG(heap_after_keygen - heap_before_keygen), 1) AS avg_heap_delta_keygen,
    ROUND(AVG(heap_after_sign - heap_before_sign), 1) AS avg_heap_delta_sign,
    ROUND(AVG(energy_keygen_mj), 4) AS avg_energy_keygen_mj,
    ROUND(AVG(energy_sign_mj), 4) AS avg_energy_sign_mj,
    ROUND(AVG(energy_verify_mj), 4) AS avg_energy_verify_mj,
    AVG(pk_size_bytes) AS avg_pk_size,
    AVG(sig_size_bytes) AS avg_sig_size
FROM trials
WHERE operation_type = 'sig'
GROUP BY algorithm;
