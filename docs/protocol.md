# Protokol Komunikasi & Skema Data — TA ML-KEM vs HQC pada ESP32

## 1. Pasangan Algoritma yang Diuji

Diuji berdasarkan kesetaraan kategori keamanan NIST:

| Security Category | ML-KEM     | HQC       |
|--------------------|------------|-----------|
| Category 1 (~AES-128) | ML-KEM-512 | HQC-128   |
| Category 3 (~AES-192) | ML-KEM-768 | HQC-192   |
| Category 5 (~AES-256) | ML-KEM-1024| HQC-256   |

Total: 6 varian algoritma diuji, dikelompokkan jadi 3 pasang perbandingan.

## 2. Alur Protokol (per trial)

```
ESP32 (client)                          Server (Python)
    |                                         |
    |--- 1. TCP connect ------------------->  |
    |                                         |
    |--- 2. INIT {algorithm, trial_id} ---->  |
    |                                         |
    |  [mulai timer round-trip]               |
    |                                         |
    |=== KeyGen (ukur waktu+heap) ===         |
    |                                         |
    |--- 3. Kirim Public Key (len-prefixed)-> |
    |                                         |     === Encaps (ukur waktu di server) ===
    |<-- 4. Terima Ciphertext (len-prefixed)- |
    |                                         |
    |=== Decaps (ukur waktu+heap) ===         |
    |                                         |
    |  [stop timer round-trip]                |
    |                                         |
    |--- 5. Kirim REPORT (JSON hasil ukur) -> |
    |                                         |     -> simpan ke SQLite
    |<-- 6. ACK ----------------------------  |
    |                                         |
    |--- 7. close / next trial -------------> |
```

Catatan penting: shared secret **tidak pernah dikirim lewat jaringan** (itu justru tujuan KEM — kedua pihak dapat shared secret yang sama tanpa mengirimnya). Validasi "sukses" dilakukan dengan cara lain (lihat §5).

## 3. Format Pesan (Wire Format)

Semua pesan pakai **length-prefixed framing**: 4 byte big-endian (uint32) berisi panjang payload, diikuti payload.

```
[4 bytes length][payload...]
```

### 3.1 INIT (client -> server)
JSON:
```json
{
  "cmd": "INIT",
  "trial_id": 1,
  "algorithm": "ML-KEM-512"
}
```

### 3.2 Public Key (client -> server)
Payload: raw bytes public key (bukan JSON, langsung binary, karena ukurannya bisa besar).

### 3.3 Ciphertext (server -> client)
Payload: raw bytes ciphertext + metadata waktu encaps, dikirim sebagai 2 pesan berurutan:
- Pesan A: raw bytes ciphertext
- Pesan B: JSON `{"encaps_time_ms": 8.1, "ct_size_bytes": 768}`

### 3.4 REPORT (client -> server, akhir tiap trial)
JSON — ini yang disimpan ke database:
```json
{
  "trial_id": 1,
  "algorithm": "ML-KEM-512",
  "security_category": 1,
  "timestamp": "2026-09-13T10:00:00Z",
  "keygen_time_ms": 12.4,
  "decaps_time_ms": 15.2,
  "encaps_time_ms": 8.1,
  "network_rtt_ms": 145.7,
  "heap_before_keygen": 210000,
  "heap_after_keygen": 205300,
  "heap_before_decaps": 204800,
  "heap_after_decaps": 204100,
  "heap_min_during_cycle": 198000,
  "pk_size_bytes": 800,
  "ct_size_bytes": 768,
  "ss_size_bytes": 32,
  "status": "success",
  "fail_reason": null,
  "retry_count": 0
}
```

## 4. Skema Tabel (SQLite) — lihat `server/schema.sql`

Kolom mengikuti field REPORT di atas, 1 baris = 1 trial.

## 5. Validasi "Sukses" tanpa Mengirim Shared Secret

Dua opsi (pilih salah satu, disarankan opsi A untuk simplicity di D3):

- **Opsi A (disarankan):** Sukses = seluruh tahap (KeyGen, kirim PK, Encaps, kirim CT, Decaps) selesai tanpa error/timeout/exception. Ini valid karena kalau salah satu tahap gagal (misal ciphertext corrupt), Decaps di liboqs akan mengembalikan error atau shared secret yang tidak konsisten dengan API-nya sendiri.
- **Opsi B (lebih ketat, opsional kalau ada waktu lebih):** Kirim **hash** (SHA-256) dari shared secret (bukan shared secret itu sendiri) dari ESP32 ke server di akhir, server bandingkan dengan hash miliknya sendiri. Ini murni untuk validasi eksperimen (bukan untuk keamanan produksi), aman dilakukan karena hash satu arah tidak membocorkan shared secret asli.

## 6. Kondisi Gagal yang Perlu Ditangani (untuk `fail_reason`)

| fail_reason | Penyebab |
|---|---|
| `wifi_disconnect` | ESP32 kehilangan koneksi WiFi |
| `tcp_timeout` | Socket timeout saat connect/send/recv |
| `tcp_connreset` | Koneksi diputus paksa |
| `keygen_error` | liboqs KeyGen mengembalikan error |
| `decaps_error` | liboqs Decaps mengembalikan error |
| `malformed_response` | Data dari server tidak sesuai format yang diharapkan |
