/**
 * @file tropic01_bridge.c
 * @brief Thin C bridge exposing libtropic ECC and TRNG operations to Python ctypes.
 *
 * Singleton: one global handle + mutex.  All exported functions acquire the
 * mutex before touching libtropic so the Python ctypes caller may be multi-
 * threaded without races.
 */

#include "tropic01_bridge.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_posix_usb_dongle.h"
#include "psa/crypto.h"

/* ------------------------------------------------------------------ */
/* Singleton state                                                      */
/* ------------------------------------------------------------------ */

static pthread_mutex_t          g_lock       = PTHREAD_MUTEX_INITIALIZER;
static lt_handle_t              g_handle;
static lt_dev_posix_usb_dongle_t g_device;
static lt_ctx_mbedtls_v4_t      g_crypto_ctx;
static int                      g_initialised = 0;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

#define LOCK()   pthread_mutex_lock(&g_lock)
#define UNLOCK() pthread_mutex_unlock(&g_lock)

static int _start_session(int use_eng_sample)
{
    const uint8_t *priv_key;
    const uint8_t *pub_key;

    if (use_eng_sample) {
        priv_key = sh0priv_eng_sample;
        pub_key  = sh0pub_eng_sample;
    } else {
        priv_key = sh0priv_prod0;
        pub_key  = sh0pub_prod0;
    }

    /* Reboot to Application FW, then start Secure Session. */
    lt_ret_t ret = lt_reboot(&g_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "[tropic01_bridge] lt_reboot failed: %s\n",
                lt_ret_verbose(ret));
        return TROPIC_FAIL;
    }

    ret = lt_verify_chip_and_start_secure_session(
              &g_handle, priv_key, pub_key,
              TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (ret != LT_OK) {
        fprintf(stderr,
                "[tropic01_bridge] lt_verify_chip_and_start_secure_session "
                "failed: %s\n", lt_ret_verbose(ret));
        return TROPIC_FAIL;
    }
    return TROPIC_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int tropic_bridge_init(const char *dev_path, int use_eng_sample)
{
    LOCK();

    if (g_initialised) {
        UNLOCK();
        return TROPIC_OK;  /* idempotent */
    }

    /* PSA Crypto must be initialised before any libtropic call. */
    psa_status_t psa_ret = psa_crypto_init();
    if (psa_ret != PSA_SUCCESS) {
        fprintf(stderr, "[tropic01_bridge] psa_crypto_init failed: %d\n",
                (int)psa_ret);
        UNLOCK();
        return TROPIC_FAIL;
    }

    memset(&g_handle,     0, sizeof(g_handle));
    memset(&g_device,     0, sizeof(g_device));
    memset(&g_crypto_ctx, 0, sizeof(g_crypto_ctx));

    /* Populate device structure. */
    int n = snprintf(g_device.dev_path, sizeof(g_device.dev_path),
                     "%s", dev_path);
    if (n < 0 || (size_t)n >= sizeof(g_device.dev_path)) {
        fprintf(stderr, "[tropic01_bridge] device path too long\n");
        mbedtls_psa_crypto_free();
        UNLOCK();
        return TROPIC_FAIL;
    }
    g_device.baud_rate = 115200;

    /* Wire device and crypto context into the handle. */
    g_handle.l2.device     = &g_device;
    g_handle.l3.crypto_ctx = &g_crypto_ctx;

    lt_ret_t ret = lt_init(&g_handle);
    if (ret != LT_OK) {
        fprintf(stderr, "[tropic01_bridge] lt_init failed: %s\n",
                lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        UNLOCK();
        return TROPIC_FAIL;
    }

    if (_start_session(use_eng_sample) != TROPIC_OK) {
        lt_deinit(&g_handle);
        mbedtls_psa_crypto_free();
        UNLOCK();
        return TROPIC_FAIL;
    }

    g_initialised = 1;
    UNLOCK();
    return TROPIC_OK;
}

void tropic_bridge_deinit(void)
{
    LOCK();
    if (!g_initialised) {
        UNLOCK();
        return;
    }
    lt_session_abort(&g_handle);
    lt_deinit(&g_handle);
    mbedtls_psa_crypto_free();
    g_initialised = 0;
    UNLOCK();
}

int tropic_bridge_get_random(uint8_t *buf, uint8_t len)
{
    if (!buf || len == 0) return TROPIC_FAIL;

    LOCK();
    if (!g_initialised) { UNLOCK(); return TROPIC_FAIL; }

    lt_ret_t ret = lt_random_value_get(&g_handle, buf, (uint16_t)len);
    UNLOCK();

    return (ret == LT_OK) ? TROPIC_OK : TROPIC_FAIL;
}

int tropic_bridge_ecc_key_generate(uint8_t slot)
{
    LOCK();
    if (!g_initialised) { UNLOCK(); return TROPIC_FAIL; }

    lt_ret_t ret = lt_ecc_key_generate(&g_handle,
                                       (lt_ecc_slot_t)slot,
                                       TR01_CURVE_P256);
    UNLOCK();

    return (ret == LT_OK) ? TROPIC_OK : TROPIC_FAIL;
}

int tropic_bridge_ecc_key_read(uint8_t slot, uint8_t *pub_out)
{
    if (!pub_out) return TROPIC_FAIL;

    LOCK();
    if (!g_initialised) { UNLOCK(); return TROPIC_FAIL; }

    lt_ecc_curve_type_t  curve;
    lt_ecc_key_origin_t  origin;
    /* P-256 public key = 64 bytes (X||Y). */
    lt_ret_t ret = lt_ecc_key_read(&g_handle,
                                   (lt_ecc_slot_t)slot,
                                   pub_out, 64,
                                   &curve, &origin);
    UNLOCK();

    if (ret != LT_OK) return TROPIC_FAIL;
    if (curve != TR01_CURVE_P256) return TROPIC_FAIL;
    return TROPIC_OK;
}

int tropic_bridge_ecdsa_sign(uint8_t slot,
                             const uint8_t *msg, uint32_t msg_len,
                             uint8_t *rs_out)
{
    if (!msg || !rs_out) return TROPIC_FAIL;

    LOCK();
    if (!g_initialised) { UNLOCK(); return TROPIC_FAIL; }

    lt_ret_t ret = lt_ecc_ecdsa_sign(&g_handle,
                                     (lt_ecc_slot_t)slot,
                                     msg, msg_len,
                                     rs_out);
    UNLOCK();

    return (ret == LT_OK) ? TROPIC_OK : TROPIC_FAIL;
}

int tropic_bridge_ecc_key_erase(uint8_t slot)
{
    LOCK();
    if (!g_initialised) { UNLOCK(); return TROPIC_FAIL; }

    lt_ret_t ret = lt_ecc_key_erase(&g_handle, (lt_ecc_slot_t)slot);
    UNLOCK();

    return (ret == LT_OK) ? TROPIC_OK : TROPIC_FAIL;
}
