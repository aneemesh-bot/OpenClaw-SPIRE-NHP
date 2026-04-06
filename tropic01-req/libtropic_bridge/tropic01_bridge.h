/**
 * @file tropic01_bridge.h
 * @brief Thin C bridge exposing libtropic ECC and TRNG operations to Python ctypes.
 *
 * Only one TROPIC01 connection is supported at a time (global singleton state).
 * Thread-safe: a mutex protects every libtropic call.
 */

#ifndef TROPIC01_BRIDGE_H
#define TROPIC01_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Return code: success. */
#define TROPIC_OK   0
/** Return code: failure. */
#define TROPIC_FAIL 1

/**
 * @brief Initialise the bridge: open the serial device, start a Secure Session.
 *
 * @param dev_path        Path to serial device, e.g. "/dev/ttyACM0".
 * @param use_eng_sample  1 → use engineering-sample pairing keys (sh0*_eng_sample);
 *                        0 → use production keys (sh0*_prod0).
 * @return TROPIC_OK on success, TROPIC_FAIL otherwise.
 */
int tropic_bridge_init(const char *dev_path, int use_eng_sample);

/**
 * @brief Abort the Secure Session and close the device.
 */
void tropic_bridge_deinit(void);

/**
 * @brief Get hardware-random bytes from TROPIC01's TRNG.
 *
 * @param buf  Output buffer.
 * @param len  Number of bytes to generate (1–255, hardware maximum per call).
 * @return TROPIC_OK on success, TROPIC_FAIL otherwise.
 */
int tropic_bridge_get_random(uint8_t *buf, uint8_t len);

/**
 * @brief Generate a P-256 ECC key pair inside TROPIC01 at the given slot.
 *
 * The private key never leaves the chip.
 *
 * @param slot  ECC slot index (0–31).
 * @return TROPIC_OK on success, TROPIC_FAIL otherwise.
 */
int tropic_bridge_ecc_key_generate(uint8_t slot);

/**
 * @brief Read the P-256 public key from a slot.
 *
 * @param slot     ECC slot index (0–31).
 * @param pub_out  64-byte output buffer: first 32 bytes = X, next 32 = Y.
 * @return TROPIC_OK on success, TROPIC_FAIL otherwise.
 */
int tropic_bridge_ecc_key_read(uint8_t slot, uint8_t *pub_out);

/**
 * @brief ECDSA P-256 sign.  TROPIC01 SHA-256-hashes @p msg internally.
 *
 * @param slot     ECC slot holding the signing key (0–31).
 * @param msg      Message bytes to sign.
 * @param msg_len  Length of @p msg.
 * @param rs_out   64-byte output buffer: first 32 bytes = R, next 32 = S.
 * @return TROPIC_OK on success, TROPIC_FAIL otherwise.
 */
int tropic_bridge_ecdsa_sign(uint8_t slot,
                             const uint8_t *msg, uint32_t msg_len,
                             uint8_t *rs_out);

/**
 * @brief Erase the ECC key in the given slot.
 *
 * @param slot  ECC slot index (0–31).
 * @return TROPIC_OK on success, TROPIC_FAIL otherwise.
 */
int tropic_bridge_ecc_key_erase(uint8_t slot);

#ifdef __cplusplus
}
#endif

#endif /* TROPIC01_BRIDGE_H */
