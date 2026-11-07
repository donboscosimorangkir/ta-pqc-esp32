import sys
from pathlib import Path

PATH = Path(sys.argv[1] if len(sys.argv) > 1 else "main/esp32_firmware.c")
s = PATH.read_text()

START = "/* ----------------- Satu trial KEM (KeyGen -> Decaps; Encaps di server) ----------------- */"
END = "/* ----------------- Abstraksi Signature (ML-DSA & SLH-DSA) ----------------- */"
INIT_OLD = '    cJSON_AddStringToObject(init_json, "algorithm", cfg->name);\n'
INIT_NEW = (INIT_OLD +
            '    if (cfg->family == FAM_MLKEM || cfg->family == FAM_HQC)\n'
            '        cJSON_AddNumberToObject(init_json, "rounds", 2);  /* KEM dua ronde */\n')

NEW_KEM = r'''/* ----------------- Abstraksi KEM (ML-KEM & HQC) ----------------- */
typedef struct {
    bool         is_mlkem;
    mlkem_ctx_t  m;
    hqc_ctx_t    h;
} kem_session_t;

static int kem_init_keypair(kem_session_t *x, const test_config_t *cfg)
{
    memset(x, 0, sizeof(*x));
    x->is_mlkem = (cfg->family == FAM_MLKEM);
    int rc;
    if (x->is_mlkem) {
        rc = mlkem_init(&x->m, cfg->level);
        if (rc == 0) rc = mlkem_keypair(&x->m);
    } else {
        rc = hqc_init(&x->h, cfg->level);
        if (rc == 0) rc = hqc_keypair(&x->h);
    }
    return rc;
}

static int kem_encaps(kem_session_t *x, const uint8_t *pk)
{
    return x->is_mlkem ? mlkem_encaps(&x->m, pk) : hqc_encaps(&x->h, pk);
}

static int kem_decaps(kem_session_t *x, const uint8_t *ct)
{
    return x->is_mlkem ? mlkem_decaps(&x->m, ct) : hqc_decaps(&x->h, ct);
}

static const uint8_t *kem_pk(const kem_session_t *x)  { return x->is_mlkem ? x->m.public_key   : x->h.public_key; }
static const uint8_t *kem_ct(const kem_session_t *x)  { return x->is_mlkem ? x->m.ciphertext    : x->h.ciphertext; }
static const uint8_t *kem_ss(const kem_session_t *x)  { return x->is_mlkem ? x->m.shared_secret : x->h.shared_secret; }
static size_t kem_pk_len(kem_session_t *x) { return x->is_mlkem ? mlkem_get_public_key_len(&x->m)    : hqc_get_public_key_len(&x->h); }
static size_t kem_ct_len(kem_session_t *x) { return x->is_mlkem ? mlkem_get_ciphertext_len(&x->m)    : hqc_get_ciphertext_len(&x->h); }
static size_t kem_ss_len(kem_session_t *x) { return x->is_mlkem ? mlkem_get_shared_secret_len(&x->m) : hqc_get_shared_secret_len(&x->h); }

static void kem_cleanup(kem_session_t *x)
{
    if (x->is_mlkem) mlkem_cleanup(&x->m); else hqc_cleanup(&x->h);
}

/* ----------------- Satu trial KEM, DUA RONDE -----------------
 * Supaya KeyGen, Encaps, dan Decaps SEMUANYA terukur di ESP32:
 *   Ronde 1: ESP32 KeyGen -> kirim PK -> server Encaps -> ESP32 Decaps
 *   Ronde 2: peran ditukar. Server KeyGen -> kirim PK2 -> ESP32 Encaps
 *            -> kirim CT2 -> server Decaps
 * Shared secret kedua ronde dikirim (hex) agar server bisa memvalidasinya.
 * Context ronde 1 dipakai ulang untuk Encaps (buffer sudah teralokasi), jadi
 * pengukuran heap Encaps tidak bercampur dengan biaya alokasi. */
static bool run_trial_kem(const test_config_t *cfg, int trial_id)
{
    int retry = 0;
    bool success = false;

    while (retry <= MAX_RETRY && !success) {
        int sock; int64_t t_rtt0;
        if (connect_and_init(cfg, trial_id, retry, &sock, &t_rtt0) != 0) { retry++; continue; }

        kem_session_t kx;
        memset(&kx, 0, sizeof(kx));
        kx.is_mlkem = (cfg->family == FAM_MLKEM);
        uint8_t *ct = NULL, *meta_raw = NULL, *pk2 = NULL, *ack = NULL;
        uint32_t ct_len = 0, meta_len = 0, pk2_len = 0, ack_len = 0;
        char *ss1_hex = NULL, *ss2_hex = NULL;
        int dc_rc = -1, en_rc = -1;
        double keygen_ms = 0, decaps_ms = 0, encaps_ms = 0;
        uint32_t hb_kg = 0, ha_kg = 0, hb_dc = 0, ha_dc = 0, hb_en = 0, ha_en = 0;
        bool ok = false;

        /* ===== RONDE 1: KeyGen + Decaps di ESP32 ===== */
        hb_kg = esp_get_free_heap_size();
        int64_t t0 = esp_timer_get_time();
        int kg_rc = kem_init_keypair(&kx, cfg);
        keygen_ms = (esp_timer_get_time() - t0) / 1000.0;
        ha_kg = esp_get_free_heap_size();
        if (kg_rc != 0) {
            ESP_LOGE(TAG, "Trial %d [%s]: KeyGen gagal", trial_id, cfg->name);
            goto cleanup;
        }

        if (send_framed(sock, kem_pk(&kx), (uint32_t)kem_pk_len(&kx)) != 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: kirim PK gagal", trial_id, cfg->name);
            goto cleanup;
        }

        if (recv_framed(sock, &ct, &ct_len) != 0 || recv_framed(sock, &meta_raw, &meta_len) != 0 ||
            ct == NULL || ct_len != kem_ct_len(&kx)) {
            ESP_LOGW(TAG, "Trial %d [%s]: terima CT/meta gagal", trial_id, cfg->name);
            goto cleanup;
        }
        free(meta_raw); meta_raw = NULL;   /* metadata Encaps server (PC) dicatat server sendiri */

        hb_dc = esp_get_free_heap_size();
        t0 = esp_timer_get_time();
        dc_rc = kem_decaps(&kx, ct);
        decaps_ms = (esp_timer_get_time() - t0) / 1000.0;
        ha_dc = esp_get_free_heap_size();
        size_t ss_len = kem_ss_len(&kx);
        if (dc_rc == 0) ss1_hex = hex_encode(kem_ss(&kx), ss_len);   /* simpan sebelum Encaps menimpa */

        /* ===== RONDE 2: Encaps di ESP32 (peran ditukar) ===== */
        if (recv_framed(sock, &pk2, &pk2_len) != 0 || pk2 == NULL || pk2_len != kem_pk_len(&kx)) {
            ESP_LOGW(TAG, "Trial %d [%s]: terima PK ronde 2 gagal", trial_id, cfg->name);
            goto cleanup;
        }

        hb_en = esp_get_free_heap_size();
        t0 = esp_timer_get_time();
        en_rc = kem_encaps(&kx, pk2);
        encaps_ms = (esp_timer_get_time() - t0) / 1000.0;
        ha_en = esp_get_free_heap_size();
        if (en_rc != 0) {
            ESP_LOGE(TAG, "Trial %d [%s]: Encaps gagal", trial_id, cfg->name);
            goto cleanup;
        }

        if (send_framed(sock, kem_ct(&kx), (uint32_t)kem_ct_len(&kx)) != 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: kirim CT ronde 2 gagal", trial_id, cfg->name);
            goto cleanup;
        }
        ss2_hex = hex_encode(kem_ss(&kx), kem_ss_len(&kx));
        double network_rtt_ms = (esp_timer_get_time() - t_rtt0) / 1000.0;

        /* ===== REPORT ===== */
        ok = (dc_rc == 0 && en_rc == 0);
        cJSON *report = cJSON_CreateObject();
        cJSON_AddNumberToObject(report, "trial_id", trial_id);
        cJSON_AddStringToObject(report, "algorithm", cfg->name);
        cJSON_AddNumberToObject(report, "security_category", cfg->security_category);
        cJSON_AddNumberToObject(report, "keygen_time_ms", keygen_ms);
        cJSON_AddNumberToObject(report, "decaps_time_ms", decaps_ms);
        cJSON_AddNumberToObject(report, "encaps_time_ms", encaps_ms);   /* diukur di ESP32 (ronde 2) */
        cJSON_AddNumberToObject(report, "network_rtt_ms", network_rtt_ms);
        cJSON_AddNumberToObject(report, "heap_before_keygen", hb_kg);
        cJSON_AddNumberToObject(report, "heap_after_keygen", ha_kg);
        cJSON_AddNumberToObject(report, "heap_before_decaps", hb_dc);
        cJSON_AddNumberToObject(report, "heap_after_decaps", ha_dc);
        cJSON_AddNumberToObject(report, "heap_before_encaps", hb_en);
        cJSON_AddNumberToObject(report, "heap_after_encaps", ha_en);
        cJSON_AddNumberToObject(report, "ss_size_bytes", (double)ss_len);
        cJSON_AddStringToObject(report, "status", ok ? "success" : "fail");
        if (!ok) cJSON_AddStringToObject(report, "fail_reason", dc_rc != 0 ? "decaps_error" : "encaps_error");
        cJSON_AddNumberToObject(report, "retry_count", retry);
        if (ss1_hex) cJSON_AddStringToObject(report, "ss_hex", ss1_hex);
        if (ss2_hex) cJSON_AddStringToObject(report, "ss2_hex", ss2_hex);

        char *report_str = cJSON_PrintUnformatted(report);
        send_framed(sock, (uint8_t *)report_str, strlen(report_str));
        free(report_str); cJSON_Delete(report);

        recv_framed(sock, &ack, &ack_len);

        ESP_LOGI(TAG, "Trial %d [%s]: %s (keygen=%.3fms encaps=%.3fms decaps=%.3fms rtt=%.3fms)",
                 trial_id, cfg->name, ok ? "SUKSES" : "GAGAL",
                 keygen_ms, encaps_ms, decaps_ms, network_rtt_ms);

cleanup:
        free(ct); free(meta_raw); free(pk2); free(ack);
        free(ss1_hex); free(ss2_hex);
        kem_cleanup(&kx);
        close(sock);
        if (ok) success = true; else retry++;
    }
    return success;
}

'''

if START not in s or END not in s or INIT_OLD not in s:
    sys.exit("[GAGAL] penanda tidak ditemukan; file tidak diubah. Kirim hasil 'grep -n \"Satu trial KEM\\|Abstraksi Signature\" main/esp32_firmware.c'.")
a, b = s.index(START), s.index(END)
s = s[:a] + NEW_KEM + s[b:]
s = s.replace(INIT_OLD, INIT_NEW, 1)
PATH.write_text(s)
print(f"[OK] {PATH} diperbarui (KEM dua ronde)")
