#include <stdio.h>
#include <string.h>
#include <time.h>
#include "slhdsa_generic.h"

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

#define CHECK(cond, label) do { \
    if (cond) printf("  [ok]   %s\n", label); \
    else { printf("  [FAIL] %s\n", label); fails++; } } while (0)

static int run(int level, size_t e_pk, size_t e_sk, size_t e_sig)
{
    slhdsa_ctx_t c;
    uint8_t msg[64], sig1[SLHDSA_MAX_SIG_LEN];
    int fails = 0;
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    printf("\n== level %d ==\n", level);
    CHECK(slhdsa_init(&c, level) == SLHDSA_OK, "init");
    printf("  nama: %s\n", slhdsa_name(&c));
    CHECK(slhdsa_pk_len(&c) == e_pk && slhdsa_sk_len(&c) == e_sk &&
          slhdsa_sig_max_len(&c) == e_sig, "ukuran pk/sk/sig sesuai FIPS 205");

    double t0 = now_ms();
    CHECK(slhdsa_keypair(&c) == SLHDSA_OK, "keypair");
    double t1 = now_ms();
    CHECK(slhdsa_sign(&c, msg, sizeof(msg)) == SLHDSA_OK, "sign");
    double t2 = now_ms();
    CHECK(slhdsa_sig_len(&c) == e_sig, "panjang signature == ukuran tetap");
    CHECK(slhdsa_verify(&c, msg, sizeof(msg), NULL) == SLHDSA_OK, "verify (pk internal)");
    double t3 = now_ms();
    printf("  (waktu PC, bukan data TA) keypair %.1f ms | sign %.1f ms | verify %.1f ms\n",
           t1 - t0, t2 - t1, t3 - t2);

    uint8_t pkcopy[SLHDSA_MAX_PK_LEN];
    memcpy(pkcopy, c.pk, c.pk_len);
    CHECK(slhdsa_verify(&c, msg, sizeof(msg), pkcopy) == SLHDSA_OK, "verify (pk eksternal)");

    c.sig[0] ^= 1;
    CHECK(slhdsa_verify(&c, msg, sizeof(msg), NULL) == SLHDSA_ERR_VERIFY, "signature rusak ditolak");
    c.sig[0] ^= 1;

    uint8_t bad[64]; memcpy(bad, msg, 64); bad[10] ^= 1;
    CHECK(slhdsa_verify(&c, bad, sizeof(bad), NULL) == SLHDSA_ERR_VERIFY, "pesan berubah ditolak");

    pkcopy[0] ^= 1;
    CHECK(slhdsa_verify(&c, msg, sizeof(msg), pkcopy) == SLHDSA_ERR_VERIFY, "public key salah ditolak");

    memcpy(sig1, c.sig, c.sig_len);
    CHECK(slhdsa_sign(&c, msg, sizeof(msg)) == SLHDSA_OK, "sign kedua");
    CHECK(memcmp(sig1, c.sig, c.sig_len) != 0, "signature berbeda tiap sign (randomized)");
    CHECK(slhdsa_verify(&c, msg, sizeof(msg), NULL) == SLHDSA_OK, "verify sign kedua");

    slhdsa_cleanup(&c);
    printf("  hasil level %d: %s\n", level, fails ? "GAGAL" : "LULUS");
    return fails;
}

int main(void)
{
    int f = 0;
    f += run(1,  32,  64,  7856);
    f += run(3,  48,  96,  16224);
    f += run(5,  64, 128,  29792);
    printf("\n=== TOTAL: %s (%d gagal) ===\n", f ? "GAGAL" : "SEMUA LULUS", f);
    return f ? 1 : 0;
}
