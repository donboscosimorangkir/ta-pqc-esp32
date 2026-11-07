#!/usr/bin/env python3
"""
Server pengujian PQC pada ESP32-WROOM-32:
  - Key Establishment : ML-KEM (512/768/1024) dan HQC (1/3/5)
  - Digital Signature : ML-DSA (44/65/87) dan SLH-DSA (SHAKE 128s/192s/256s)

Alur KEM (operation_type = 'kem'), dua ronde supaya KeyGen, Encaps, dan Decaps
SEMUANYA diukur di ESP32:
  INIT (rounds=2)
  Ronde 1: terima Public Key client -> Encaps (server) -> kirim Ciphertext + metadata
  Ronde 2: peran ditukar. Server KeyGen -> kirim Public Key -> terima Ciphertext
           hasil Encaps ESP32 -> Decaps (server)
  -> terima REPORT client -> bandingkan shared secret kedua ronde -> ACK
  (Client lama tanpa 'rounds' di INIT dilayani 1 ronde saja.)

Alur Signature (operation_type = 'sig'):
  INIT -> kirim pesan uji -> terima Public Key + Signature -> Verify (server)
       -> kirim metadata verify -> terima REPORT client -> ACK

Requirement:
    pip install liboqs-python

Jalankan:
    python server.py --host 0.0.0.0 --port 9000 --db results.db
"""

import argparse
import datetime
import json
import os
import socket
import sqlite3
import struct
import time
import traceback
from pathlib import Path

import oqs  # liboqs-python

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Pemetaan algoritma -> (family, security_category, operation_type)
# Catatan: ML-DSA-44 mengklaim level NIST 2 (bukan 1), sedangkan
# SLH-DSA-128s mengklaim level 1. Pasangan "setara" untuk laporan
# (44<->128s, 65<->192s, 87<->256s) adalah pasangan per-tingkat,
# bukan kategori NIST yang identik.
ALGORITHM_INFO = {
    "ML-KEM-512":  ("ML-KEM", 1, "kem"),
    "ML-KEM-768":  ("ML-KEM", 3, "kem"),
    "ML-KEM-1024": ("ML-KEM", 5, "kem"),
    "HQC-1":       ("HQC", 1, "kem"),
    "HQC-3":       ("HQC", 3, "kem"),
    "HQC-5":       ("HQC", 5, "kem"),
    "ML-DSA-44":   ("ML-DSA", 2, "sig"),
    "ML-DSA-65":   ("ML-DSA", 3, "sig"),
    "ML-DSA-87":   ("ML-DSA", 5, "sig"),
    "SLH_DSA_PURE_SHAKE_128S": ("SLH-DSA", 1, "sig"),
    "SLH_DSA_PURE_SHAKE_192S": ("SLH-DSA", 3, "sig"),
    "SLH_DSA_PURE_SHAKE_256S": ("SLH-DSA", 5, "sig"),
    # Nama yang dikirim firmware ESP32 (dipetakan ke nama liboqs lewat OQS_NAME)
    "SLH-DSA-SHAKE-128s": ("SLH-DSA", 1, "sig"),
    "SLH-DSA-SHAKE-192s": ("SLH-DSA", 3, "sig"),
    "SLH-DSA-SHAKE-256s": ("SLH-DSA", 5, "sig"),
}

# Alias nama firmware -> nama mekanisme di liboqs
OQS_NAME = {
    "SLH-DSA-SHAKE-128s": "SLH_DSA_PURE_SHAKE_128S",
    "SLH-DSA-SHAKE-192s": "SLH_DSA_PURE_SHAKE_192S",
    "SLH-DSA-SHAKE-256s": "SLH_DSA_PURE_SHAKE_256S",
}

# Kolom yang ditambahkan oleh protokol dua ronde (untuk migrasi database lama)
NEW_COLS = {
    "server_encaps_time_ms": "REAL",
    "heap_before_encaps": "INTEGER",
    "heap_after_encaps": "INTEGER",
    "kem_rounds": "INTEGER",
}


ENERGY_COLS = {
    "energy_keygen_mj": "REAL",
    "energy_encaps_mj": "REAL",
    "energy_decaps_mj": "REAL",
    "energy_sign_mj": "REAL",
    "energy_verify_mj": "REAL",
    "energy_samples_min": "INTEGER",
    "idle_power_mw": "REAL",
    "ina_available": "INTEGER",
}


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='trials'"
    ).fetchone()
    if row:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(trials)")}
        if "operation_type" not in cols:
            conn.close()
            raise SystemExit(
                f"[!] {db_path} memakai skema lama (belum ada kolom operation_type). "
                "Jalankan lagi dengan --db <nama file baru>."
            )
        for col, typ in {**NEW_COLS, **ENERGY_COLS}.items():  # migrasi otomatis
            if col not in cols:
                conn.execute(f"ALTER TABLE trials ADD COLUMN {col} {typ}")
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    return conn


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Terima persis n bytes dari socket (menangani partial recv)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi terputus saat menerima data")
        buf.extend(chunk)
    return bytes(buf)


def recv_framed(sock: socket.socket) -> bytes:
    """Terima 1 pesan dengan format [4 byte length][payload]."""
    length_bytes = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", length_bytes)
    if length == 0:
        return b""
    return recv_exact(sock, length)


def send_framed(sock: socket.socket, payload: bytes) -> None:
    """Kirim 1 pesan dengan format [4 byte length][payload]."""
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def run_kem_trial(client_sock: socket.socket, algorithm: str, report: dict, rounds: int) -> None:
    # --- RONDE 1: ESP32 = KeyGen + Decaps, server = Encaps ---
    pk_bytes = recv_framed(client_sock)
    print(f"    PK diterima len={len(pk_bytes)} head={pk_bytes[:16].hex()} tail={pk_bytes[-16:].hex()}", flush=True)
    if algorithm.startswith("ML-KEM"):
        t = pk_bytes[:-32]
        bad = 0
        for i in range(0, len(t) - 2, 3):
            a = t[i] | ((t[i + 1] & 0x0F) << 8)
            b = (t[i + 1] >> 4) | (t[i + 2] << 4)
            bad += (a >= 3329) + (b >= 3329)
        print(f"    cek modulus ML-KEM: koefisien tidak valid={bad} (0 = PK valid)", flush=True)

    with oqs.KeyEncapsulation(algorithm) as server_kem:
        t0 = time.perf_counter()
        ciphertext, shared_secret_server = server_kem.encap_secret(pk_bytes)
        encaps_time_ms = (time.perf_counter() - t0) * 1000.0

    send_framed(client_sock, ciphertext)
    meta = {
        "encaps_time_ms": round(encaps_time_ms, 4),
        "ct_size_bytes": len(ciphertext),
        "pk_size_bytes": len(pk_bytes),
    }
    send_framed(client_sock, json.dumps(meta).encode("utf-8"))

    # --- RONDE 2: peran ditukar. Server = KeyGen + Decaps, ESP32 = Encaps ---
    shared_secret_r2 = None
    if rounds >= 2:
        with oqs.KeyEncapsulation(algorithm) as r2_kem:
            pk2 = r2_kem.generate_keypair()
            send_framed(client_sock, pk2)
            ct2 = recv_framed(client_sock)
            shared_secret_r2 = r2_kem.decap_secret(ct2)

    # --- Terima REPORT lengkap dari client ---
    client_report = json.loads(recv_framed(client_sock).decode("utf-8"))
    ss_hex_client = client_report.pop("ss_hex", None)
    ss2_hex_client = client_report.pop("ss2_hex", None)

    report.update(client_report)
    report["server_encaps_time_ms"] = round(encaps_time_ms, 4)
    report["pk_size_bytes"] = len(pk_bytes)
    report["ct_size_bytes"] = len(ciphertext)
    report["kem_rounds"] = 2 if rounds >= 2 else 1
    if rounds < 2:
        # Protokol lama: Encaps diukur di server PC
        report["encaps_time_ms"] = round(encaps_time_ms, 4)
    if report.get("status") is None:
        report["status"] = "success"

    # Validasi: shared secret client harus sama dengan milik server di tiap ronde.
    # (client lama yang tidak mengirim ss_hex dilewati agar tetap kompatibel)
    if ss_hex_client is not None and ss_hex_client.lower() != shared_secret_server.hex():
        report["status"] = "fail"
        report["fail_reason"] = "shared_secret_mismatch"
    if rounds >= 2:
        if ss2_hex_client is None:
            report["status"] = "fail"
            report["fail_reason"] = report.get("fail_reason") or "ronde2_tidak_lengkap"
        elif ss2_hex_client.lower() != shared_secret_r2.hex():
            report["status"] = "fail"
            report["fail_reason"] = "shared_secret_mismatch_r2"

    send_framed(client_sock, b"ACK")


def run_sig_trial(client_sock: socket.socket, algorithm: str, report: dict, msg_len: int) -> None:
    # --- Kirim pesan uji ---
    message = os.urandom(msg_len)
    send_framed(client_sock, message)

    # --- Terima Public Key + Signature (client melakukan KeyGen + Sign) ---
    pk_bytes = recv_framed(client_sock)
    signature = recv_framed(client_sock)

    # --- Verify independen di server ---
    with oqs.Signature(OQS_NAME.get(algorithm, algorithm)) as verifier:
        t0 = time.perf_counter()
        verify_ok = bool(verifier.verify(message, signature, pk_bytes))
        server_verify_time_ms = (time.perf_counter() - t0) * 1000.0

    meta = {
        "verify_ok": verify_ok,
        "server_verify_time_ms": round(server_verify_time_ms, 4),
        "sig_size_bytes": len(signature),
        "pk_size_bytes": len(pk_bytes),
    }
    send_framed(client_sock, json.dumps(meta).encode("utf-8"))

    # --- Terima REPORT lengkap dari client ---
    client_report = json.loads(recv_framed(client_sock).decode("utf-8"))
    client_report.pop("ss_hex", None)

    report.update(client_report)
    report["server_verify_time_ms"] = round(server_verify_time_ms, 4)
    report["pk_size_bytes"] = len(pk_bytes)
    report["sig_size_bytes"] = len(signature)
    if report.get("status") is None:
        report["status"] = "success"
    if not verify_ok:
        report["status"] = "fail"
        report["fail_reason"] = report.get("fail_reason") or "server_verify_failed"

    send_framed(client_sock, b"ACK")


def handle_client(conn, client_sock, client_addr, timeout_s: float, sig_timeout_s: float, msg_len: int) -> None:
    print(f"[+] Koneksi dari {client_addr}")

    try:
        while True:
            client_sock.settimeout(timeout_s)

            # --- INIT ---
            try:
                init_raw = recv_framed(client_sock)
            except (ConnectionError, socket.timeout):
                print(f"[-] {client_addr} menutup koneksi / timeout, selesai.")
                break

            if not init_raw:
                break

            init_msg = json.loads(init_raw.decode("utf-8"))
            algorithm = init_msg["algorithm"]
            trial_id = init_msg["trial_id"]
            rounds = int(init_msg.get("rounds", 1))
            family, category, op_type = ALGORITHM_INFO.get(algorithm, ("UNKNOWN", 0, "kem"))
            print(f"    Trial {trial_id} | {algorithm} ({op_type})" + (f" ronde={rounds}" if op_type == "kem" else ""))

            # Signature bisa lama di ESP32 (terutama SLH-DSA) -> timeout lebih longgar
            if op_type == "sig":
                client_sock.settimeout(sig_timeout_s)

            report = {
                "trial_id": trial_id,
                "algorithm": algorithm,
                "algorithm_family": family,
                "operation_type": op_type,
                "security_category": category,
                "status": "fail",
                "fail_reason": None,
                "client_ip": client_addr[0],
            }

            try:
                if op_type == "sig":
                    run_sig_trial(client_sock, algorithm, report, msg_len)
                else:
                    run_kem_trial(client_sock, algorithm, report, rounds)
            except Exception as e:
                report["status"] = "fail"
                report["fail_reason"] = f"{type(e).__name__}: {e}"
                traceback.print_exc()

            save_report(conn, report)

    finally:
        client_sock.close()
        print(f"[-] {client_addr} disconnect")


def save_report(conn: sqlite3.Connection, report: dict) -> None:
    cols = [
        "trial_id", "algorithm", "algorithm_family", "operation_type",
        "security_category", "timestamp",
        "keygen_time_ms", "decaps_time_ms", "encaps_time_ms", "server_encaps_time_ms",
        "sign_time_ms", "verify_time_ms", "server_verify_time_ms", "network_rtt_ms",
        "heap_before_keygen", "heap_after_keygen", "heap_before_decaps", "heap_after_decaps",
        "heap_before_encaps", "heap_after_encaps",
        "heap_before_sign", "heap_after_sign", "heap_min_during_cycle",
        "energy_keygen_mj", "energy_encaps_mj", "energy_decaps_mj",
        "energy_sign_mj", "energy_verify_mj", "energy_samples_min",
        "idle_power_mw", "ina_available",
        "pk_size_bytes", "ct_size_bytes", "ss_size_bytes", "sig_size_bytes",
        "status", "fail_reason", "retry_count", "kem_rounds", "client_ip",
    ]
    report.setdefault(
        "timestamp",
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    values = [report.get(c) for c in cols]

    placeholders = ", ".join(["?"] * len(cols))
    conn.execute(
        f"INSERT INTO trials ({', '.join(cols)}) VALUES ({placeholders})",
        values,
    )
    conn.commit()

    if report.get("operation_type") == "sig":
        detail = (f"keygen={report.get('keygen_time_ms')}ms sign={report.get('sign_time_ms')}ms "
                  f"verify={report.get('verify_time_ms')}ms")
        if report.get("energy_sign_mj") is not None:
            detail += f" | E sign={report.get('energy_sign_mj'):.4f}mJ"
    else:
        detail = (f"keygen={report.get('keygen_time_ms')}ms encaps={report.get('encaps_time_ms')}ms "
                  f"decaps={report.get('decaps_time_ms')}ms")
        if report.get("energy_keygen_mj") is not None:
            detail += f" | E keygen={report.get('energy_keygen_mj'):.4f}mJ"
    reason = f" ({report.get('fail_reason')})" if report.get("status") != "success" else ""
    print(f"    -> Disimpan: status={report.get('status')}{reason} {detail}")


def main():
    parser = argparse.ArgumentParser(description="Server pengujian PQC (KEM + Signature)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--db", default="results.db")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="timeout socket (detik) untuk alur KEM")
    parser.add_argument("--sig-timeout", type=float, default=900.0,
                        help="timeout socket (detik) untuk alur signature "
                             "(harus > waktu Sign di ESP32, SLH-DSA bisa lama)")
    parser.add_argument("--msg-len", type=int, default=256,
                        help="panjang pesan uji (byte) untuk signature")
    args = parser.parse_args()

    conn = init_db(args.db)
    print(f"[i] Database siap: {args.db}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen(5)
        print(f"[i] Listening di {args.host}:{args.port} ...")

        try:
            while True:
                client_sock, client_addr = server_sock.accept()
                handle_client(conn, client_sock, client_addr,
                              args.timeout, args.sig_timeout, args.msg_len)
        except KeyboardInterrupt:
            print("\n[i] Server dihentikan.")
        finally:
            conn.close()


if __name__ == "__main__":
    main()
