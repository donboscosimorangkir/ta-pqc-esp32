"""
Dummy client - simulasi ESP32 memakai Python + liboqs-python.

Tujuan: validasi seluruh pipeline (protokol, server, logging, analisis)
SEBELUM hardware ESP32 fisik tersedia. Protokolnya identik dengan firmware
(esp32_firmware.c), termasuk KEM dua ronde:
  Ronde 1: client KeyGen + Decaps (server Encaps)
  Ronde 2: peran ditukar, client Encaps (server KeyGen + Decaps)

Catatan:
  - Field heap_* di sini DIISI DUMMY (None), karena PC tidak punya konsep
    "free heap" seperti MCU. Nanti diisi sungguhan oleh firmware ESP32.
  - Waktu keygen/encaps/decaps/sign/verify diukur SUNGGUHAN (time.perf_counter()),
    tapi angka mutlaknya jauh lebih cepat dari ESP32.
  - Jenis algoritma (KEM atau Signature) dikenali otomatis dari daftar
    mekanisme liboqs.

Jalankan:
    python dummy_client.py --host 127.0.0.1 --port 9000 \
        --algorithms ML-KEM-512 HQC-1 ML-DSA-44 --trials 10
    (tambahkan --kem-rounds 1 untuk meniru firmware lama satu ronde)
"""

import argparse
import datetime
import json
import socket
import struct
import time

import oqs  # liboqs-python

# Alias nama firmware ESP32 -> nama mekanisme liboqs (sama seperti di server.py)
OQS_NAME = {
    "SLH-DSA-SHAKE-128s": "SLH_DSA_PURE_SHAKE_128S",
    "SLH-DSA-SHAKE-192s": "SLH_DSA_PURE_SHAKE_192S",
    "SLH-DSA-SHAKE-256s": "SLH_DSA_PURE_SHAKE_256S",
}


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi terputus saat menerima data")
        buf.extend(chunk)
    return bytes(buf)


def recv_framed(sock: socket.socket) -> bytes:
    length_bytes = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", length_bytes)
    if length == 0:
        return b""
    return recv_exact(sock, length)


def send_framed(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def do_kem(sock, algorithm, trial_id, t_rtt_start, retry_count, rounds) -> dict:
    # --- Ronde 1: client KeyGen + Decaps ---
    with oqs.KeyEncapsulation(algorithm) as client_kem:
        t0 = time.perf_counter()
        public_key = client_kem.generate_keypair()
        keygen_time_ms = (time.perf_counter() - t0) * 1000.0

        send_framed(sock, public_key)

        ciphertext = recv_framed(sock)
        meta = json.loads(recv_framed(sock).decode("utf-8"))  # metadata server (encaps time dst)

        t0 = time.perf_counter()
        shared_secret_client = client_kem.decap_secret(ciphertext)
        decaps_time_ms = (time.perf_counter() - t0) * 1000.0

    encaps_time_ms = meta.get("encaps_time_ms")  # protokol lama: Encaps diukur di server
    ss2_hex = None

    # --- Ronde 2: peran ditukar, client Encaps ---
    if rounds >= 2:
        pk2 = recv_framed(sock)
        with oqs.KeyEncapsulation(algorithm) as r2_kem:
            t0 = time.perf_counter()
            ct2, ss2 = r2_kem.encap_secret(pk2)
            encaps_time_ms = (time.perf_counter() - t0) * 1000.0
        send_framed(sock, ct2)
        ss2_hex = ss2.hex()

    network_rtt_ms = (time.perf_counter() - t_rtt_start) * 1000.0

    report = {
        "trial_id": trial_id,
        "algorithm": algorithm,
        "timestamp": now_iso(),
        "keygen_time_ms": round(keygen_time_ms, 4),
        "decaps_time_ms": round(decaps_time_ms, 4),
        "encaps_time_ms": round(encaps_time_ms, 4) if encaps_time_ms is not None else None,
        "network_rtt_ms": round(network_rtt_ms, 4),
        # Placeholder -- diisi sungguhan oleh firmware ESP32 nanti:
        "heap_before_keygen": None,
        "heap_after_keygen": None,
        "heap_before_decaps": None,
        "heap_after_decaps": None,
        "heap_before_encaps": None,
        "heap_after_encaps": None,
        "heap_min_during_cycle": None,
        "ss_size_bytes": len(shared_secret_client),
        "ss_hex": shared_secret_client.hex(),
        "status": "success",
        "fail_reason": None,
        "retry_count": retry_count,
    }
    if ss2_hex is not None:
        report["ss2_hex"] = ss2_hex
    return report


def do_sig(sock, algorithm, trial_id, t_rtt_start, retry_count) -> dict:
    message = recv_framed(sock)

    with oqs.Signature(OQS_NAME.get(algorithm, algorithm)) as signer:
        t0 = time.perf_counter()
        public_key = signer.generate_keypair()
        keygen_time_ms = (time.perf_counter() - t0) * 1000.0

        t0 = time.perf_counter()
        signature = signer.sign(message)
        sign_time_ms = (time.perf_counter() - t0) * 1000.0

        # Verify lokal (di ESP32 nyata: diukur di device)
        t0 = time.perf_counter()
        local_ok = bool(signer.verify(message, signature, public_key))
        verify_time_ms = (time.perf_counter() - t0) * 1000.0

    send_framed(sock, public_key)
    send_framed(sock, signature)

    meta = json.loads(recv_framed(sock).decode("utf-8"))
    network_rtt_ms = (time.perf_counter() - t_rtt_start) * 1000.0

    ok = local_ok and bool(meta.get("verify_ok"))
    return {
        "trial_id": trial_id,
        "algorithm": algorithm,
        "timestamp": now_iso(),
        "keygen_time_ms": round(keygen_time_ms, 4),
        "sign_time_ms": round(sign_time_ms, 4),
        "verify_time_ms": round(verify_time_ms, 4),
        "network_rtt_ms": round(network_rtt_ms, 4),
        "heap_before_keygen": None,
        "heap_after_keygen": None,
        "heap_before_sign": None,
        "heap_after_sign": None,
        "heap_min_during_cycle": None,
        "sig_size_bytes": len(signature),
        "status": "success" if ok else "fail",
        "fail_reason": None if ok else ("local_verify_failed" if not local_ok else "server_verify_failed"),
        "retry_count": retry_count,
    }


def run_trial(host: str, port: int, algorithm: str, trial_id: int, rounds: int, retry_left: int = 2) -> dict:
    """Jalankan 1 siklus lengkap sesuai jenis algoritma (KEM atau Signature)."""
    is_sig = OQS_NAME.get(algorithm, algorithm) in oqs.get_enabled_sig_mechanisms()
    t_rtt_start = time.perf_counter()
    retry_count = 0

    while True:
        try:
            with socket.create_connection((host, port), timeout=10.0) as sock:
                sock.settimeout(900.0 if is_sig else 15.0)

                init_msg = {"cmd": "INIT", "trial_id": trial_id, "algorithm": algorithm}
                if not is_sig:
                    init_msg["rounds"] = rounds
                send_framed(sock, json.dumps(init_msg).encode("utf-8"))

                if is_sig:
                    report = do_sig(sock, algorithm, trial_id, t_rtt_start, retry_count)
                else:
                    report = do_kem(sock, algorithm, trial_id, t_rtt_start, retry_count, rounds)

                send_framed(sock, json.dumps(report).encode("utf-8"))
                recv_framed(sock)  # tunggu ACK dari server
                report.pop("ss_hex", None)
                report.pop("ss2_hex", None)
                return report

        except (ConnectionError, socket.timeout, OSError) as e:
            retry_count += 1
            if retry_left <= 0:
                return {
                    "trial_id": trial_id,
                    "algorithm": algorithm,
                    "status": "fail",
                    "fail_reason": f"{type(e).__name__}: {e}",
                    "retry_count": retry_count,
                }
            print(f"    [!] Trial {trial_id} gagal ({e}), retry... ({retry_left} sisa)")
            retry_left -= 1
            time.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(description="Dummy client (simulasi ESP32)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--algorithms", nargs="+", required=True,
                        help="e.g. ML-KEM-512 HQC-1 ML-DSA-44 SLH-DSA-SHAKE-128s")
    parser.add_argument("--trials", type=int, default=10,
                        help="Jumlah trial per algoritma")
    parser.add_argument("--kem-rounds", type=int, default=2, choices=[1, 2],
                        help="2 = KEM dua ronde (default, seperti firmware baru); 1 = satu ronde (lama)")
    args = parser.parse_args()

    for algorithm in args.algorithms:
        print(f"\n=== Algoritma: {algorithm} ===")
        is_sig = OQS_NAME.get(algorithm, algorithm) in oqs.get_enabled_sig_mechanisms()
        for trial_id in range(1, args.trials + 1):
            result = run_trial(args.host, args.port, algorithm, trial_id, args.kem_rounds)
            status = result.get("status")
            if is_sig:
                detail = (f"keygen={result.get('keygen_time_ms')}ms, "
                          f"sign={result.get('sign_time_ms')}ms, "
                          f"verify={result.get('verify_time_ms')}ms")
            else:
                detail = (f"keygen={result.get('keygen_time_ms')}ms, "
                          f"encaps={result.get('encaps_time_ms')}ms, "
                          f"decaps={result.get('decaps_time_ms')}ms")
            print(f"  Trial {trial_id}: {status} ({detail}, rtt={result.get('network_rtt_ms')}ms)")


if __name__ == "__main__":
    main()
