# Setup — TA Analisis & Perbandingan ML-KEM vs HQC pada ESP32-WROOM-32

Panduan ini untuk dijalankan di **mesin lokal kamu** (PC/laptop dengan akses internet),
karena tahap awal (server + dummy client) tidak butuh hardware ESP32 sama sekali.

## 1. Prasyarat

- Linux (disarankan) atau WSL2 kalau di Windows. liboqs & liboqs-python paling
  lancar di Linux/macOS.
- Python 3.9+
- CMake, Ninja/Make, GCC/Clang
- Git

Cek dulu:
```bash
python3 --version
cmake --version
gcc --version
git --version
```
Kalau ada yang belum ada (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build git python3 python3-pip python3-venv
```

## 2. Install liboqs (C library)

liboqs perlu di-compile dari source dulu sebelum liboqs-python bisa dipakai.

```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
```

Verifikasi terinstall (harus ketemu file .so/.dylib):
```bash
ls /usr/local/lib | grep oqs
```

> Catatan: kalau `sudo ninja install` gagal karena permission atau kamu tidak
> mau install ke sistem, bisa pakai `-DCMAKE_INSTALL_PREFIX=$HOME/.local`
> lalu tambahkan `export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH`
> ke `~/.bashrc`.

## 3. Install liboqs-python

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install liboqs-python
```

Test cepat apakah ML-KEM dan HQC sudah bisa dipanggil:
```bash
python3 -c "
import oqs
print('ML-KEM-512' in oqs.get_enabled_kem_mechanisms())
print('HQC-128' in oqs.get_enabled_kem_mechanisms())
"
```
Kalau keduanya `True`, kamu siap lanjut. Kalau `HQC-128` muncul `False`,
kemungkinan liboqs di-build tanpa flag HQC enabled (di beberapa versi liboqs,
HQC opsional) — perlu cek opsi cmake `-DOQS_ENABLE_KEM_HQC=ON` saat build ulang.

## 4. Jalankan Server

```bash
cd server
python3 server.py --host 0.0.0.0 --port 9000 --db results.db
```
Server akan listening dan otomatis membuat `results.db` (SQLite) dari `schema.sql`.

## 5. Jalankan Dummy Client (simulasi ESP32) — di terminal lain

```bash
cd client_dummy
python3 dummy_client.py --host 127.0.0.1 --port 9000 \
    --algorithms ML-KEM-512 HQC-128 --trials 10
```

Kalau ini berhasil jalan dan di terminal server terlihat log "Disimpan: status=success"
untuk tiap trial, berarti **seluruh pipeline (protokol, server, logging) sudah tervalidasi**
dan siap ditunggu sampai hardware ESP32 datang untuk mengganti dummy client dengan
firmware sungguhan.

## 6. Cek Isi Database

```bash
sqlite3 server/results.db "SELECT * FROM summary_per_algorithm;"
```

## 7. Langkah Selanjutnya

- [ ] Scale up jumlah trial (10 -> 100) untuk lihat pipeline stabil di volume lebih besar
- [ ] Uji seluruh 6 algoritma (ML-KEM-512/768/1024, HQC-128/192/256)
- [ ] Mulai porting liboqs sebagai ESP-IDF component (ini bagian paling teknis,
      dibahas terpisah di `esp32_firmware/`)
- [ ] Setup ESP-IDF toolchain di mesin lokal (`idf.py --version` harus jalan)

## Troubleshooting Umum

| Gejala | Kemungkinan Penyebab |
|---|---|
| `ModuleNotFoundError: No module named 'oqs'` | liboqs-python belum terinstall di venv aktif |
| `OSError: liboqs library not found` | liboqs C library belum ke-install / `LD_LIBRARY_PATH` belum diset |
| Server hang / tidak terima koneksi | Cek firewall lokal, pastikan port 9000 tidak diblok |
| `HQC-128` tidak muncul di `get_enabled_kem_mechanisms()` | liboqs perlu di-build ulang dengan `-DOQS_ENABLE_KEM_HQC=ON` |
