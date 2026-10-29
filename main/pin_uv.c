#include "pin_uv.h"

#include "credential.h"
#include "platform.h"
#include "esp_random.h"
#include "nvs.h"

#include "psa/crypto.h"

#include <string.h>

static bool pin_set;
static uint8_t stored_pin_hash[16];
static bool psa_initialized;
static mbedtls_svc_key_id_t agreement_private_key = MBEDTLS_SVC_KEY_ID_INIT;
static bool agreement_private_key_ready;

#define PIN_NVS_NAMESPACE "openfido"
#define PIN_NVS_KEY "pin_hash"

static bool persist_pin(void)
{
    nvs_handle_t handle;
    esp_err_t status = nvs_open(PIN_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (status != ESP_OK) return false;
    if (pin_set) {
        status = nvs_set_blob(handle, PIN_NVS_KEY, stored_pin_hash,
                              sizeof stored_pin_hash);
    } else {
        status = nvs_erase_key(handle, PIN_NVS_KEY);
        if (status == ESP_ERR_NVS_NOT_FOUND) status = ESP_OK;
    }
    if (status == ESP_OK) status = nvs_commit(handle);
    nvs_close(handle);
    return status == ESP_OK;
}

bool pin_uv_storage_init(void)
{
    nvs_handle_t handle;
    size_t length = sizeof stored_pin_hash;
    esp_err_t status = nvs_open(PIN_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (status == ESP_ERR_NVS_NOT_FOUND) return true;
    if (status != ESP_OK) return false;
    status = nvs_get_blob(handle, PIN_NVS_KEY, stored_pin_hash, &length);
    nvs_close(handle);
    if (status == ESP_ERR_NVS_NOT_FOUND) return true;
    if (status != ESP_OK || length != sizeof stored_pin_hash) {
        memset(stored_pin_hash, 0, sizeof stored_pin_hash);
        return false;
    }
    pin_set = true;
    return true;
}

static bool crypto_init(void)
{
    if (psa_initialized) {
        return true;
    }
    if (psa_crypto_init() != PSA_SUCCESS) {
        return false;
    }
    psa_initialized = true;
    return true;
}

static void clear_ephemeral_key(void)
{
    if (agreement_private_key_ready) {
        psa_destroy_key(agreement_private_key);
        agreement_private_key = MBEDTLS_SVC_KEY_ID_INIT;
        agreement_private_key_ready = false;
    }
}

static void clear_sensitive(void)
{
    clear_ephemeral_key();
    pin_uv_clear_token();
}

bool pin_uv_configured(void)
{
    return pin_set;
}

bool pin_uv_set_from_console(const uint8_t *pin, size_t length)
{
    uint8_t hash[32];
    if (pin == NULL || length < 4 || length > 63 || !crypto_init()) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        if (pin[i] < '0' || pin[i] > '9') {
            return false;
        }
    }
    crypto_hash(pin, length, hash);
    memcpy(stored_pin_hash, hash, sizeof stored_pin_hash);
    pin_set = true;
    clear_ephemeral_key();
    pin_uv_clear_token();
    memset(hash, 0, sizeof hash);
    return persist_pin();
}

bool pin_uv_change_from_console(const uint8_t *old_pin, size_t old_length,
                                const uint8_t *new_pin, size_t new_length)
{
    uint8_t old_hash[32];
    bool matches;
    if (!pin_set || old_pin == NULL || new_pin == NULL ||
        old_length < 4 || old_length > 63 || new_length < 4 || new_length > 63 ||
        !crypto_init()) {
        return false;
    }
    for (size_t i = 0; i < old_length; i++) {
        if (old_pin[i] < '0' || old_pin[i] > '9') {
            return false;
        }
    }
    for (size_t i = 0; i < new_length; i++) {
        if (new_pin[i] < '0' || new_pin[i] > '9') {
            return false;
        }
    }
    crypto_hash(old_pin, old_length, old_hash);
    matches = memcmp(stored_pin_hash, old_hash, sizeof stored_pin_hash) == 0;
    memset(old_hash, 0, sizeof old_hash);
    if (!matches) {
        return false;
    }
    return pin_uv_set_from_console(new_pin, new_length);
}

bool pin_uv_delete(void)
{
    pin_set = false;
    memset(stored_pin_hash, 0, sizeof stored_pin_hash);
    clear_sensitive();
    return persist_pin();
}

bool pin_uv_get_key_agreement(uint8_t x[32], uint8_t y[32])
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t public_key[65];
    size_t public_key_length = 0;
    bool ok = false;

    if (x == NULL || y == NULL || !crypto_init()) {
        return false;
    }

    clear_ephemeral_key();
    memset(public_key, 0, sizeof public_key);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    if (psa_generate_key(&attributes, &agreement_private_key) != PSA_SUCCESS) {
        goto cleanup;
    }
    if (psa_export_public_key(agreement_private_key, public_key, sizeof public_key,
                              &public_key_length) != PSA_SUCCESS ||
        public_key_length != sizeof public_key || public_key[0] != 0x04) {
        goto cleanup;
    }

    memcpy(x, public_key + 1, 32);
    memcpy(y, public_key + 33, 32);
    agreement_private_key_ready = true;
    ok = true;

cleanup:
    psa_reset_key_attributes(&attributes);
    if (!ok) {
        clear_ephemeral_key();
    }
    memset(public_key, 0, sizeof public_key);
    return ok;
}

bool pin_uv_derive_shared_secret(const uint8_t x[32], const uint8_t y[32],
                                 uint8_t shared_secret[32])
{
    uint8_t peer_public_key[65];
    uint8_t ecdh_secret[32];
    size_t ecdh_secret_length = 0;
    bool ok = false;

    if (x == NULL || y == NULL || shared_secret == NULL || !crypto_init() ||
        !agreement_private_key_ready) {
        return false;
    }

    memset(peer_public_key, 0, sizeof peer_public_key);
    memset(ecdh_secret, 0, sizeof ecdh_secret);

    peer_public_key[0] = 0x04;
    memcpy(peer_public_key + 1, x, 32);
    memcpy(peer_public_key + 33, y, 32);

    if (psa_raw_key_agreement(PSA_ALG_ECDH, agreement_private_key,
                              peer_public_key, sizeof peer_public_key,
                              ecdh_secret, sizeof ecdh_secret,
                              &ecdh_secret_length) != PSA_SUCCESS ||
        ecdh_secret_length != sizeof ecdh_secret) {
        goto cleanup;
    }

    size_t hash_length = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, ecdh_secret, sizeof ecdh_secret,
                         shared_secret, 32, &hash_length) != PSA_SUCCESS ||
        hash_length != 32) {
        goto cleanup;
    }

    ok = true;

cleanup:
    clear_ephemeral_key();
    memset(peer_public_key, 0, sizeof peer_public_key);
    memset(ecdh_secret, 0, sizeof ecdh_secret);
    return ok;
}

bool pin_uv_hmac(const uint8_t key[32], const uint8_t *data, size_t length,
                 uint8_t output[32])
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    bool key_ready = false;
    bool ok = false;

    if (key == NULL || output == NULL || (length != 0 && data == NULL) || !crypto_init()) {
        return false;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, 256);

    if (psa_import_key(&attributes, key, 32, &key_id) != PSA_SUCCESS) {
        goto cleanup;
    }
    key_ready = true;
    size_t mac_length = 0;
    if (psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        data, length, output, 32, &mac_length) != PSA_SUCCESS ||
        mac_length != 32) {
        goto cleanup;
    }

    ok = true;

cleanup:
    psa_reset_key_attributes(&attributes);
    if (key_ready) {
        psa_destroy_key(key_id);
    }
    if (!ok) {
        memset(output, 0, 32);
    }
    return ok;
}

bool pin_uv_crypt(bool encrypt, const uint8_t key[32], const uint8_t *input,
                  size_t length, uint8_t *output)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    bool key_ready = false;
    uint8_t iv[16] = {0};
    size_t output_length = 0;
    size_t finish_length = 0;
    bool ok = false;
    psa_status_t status;

    if (key == NULL || input == NULL || output == NULL || length == 0 ||
        (length & 15u) != 0 || length > 64 || !crypto_init()) {
        return false;
    }

    psa_set_key_usage_flags(&attributes,
                            encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes, key, 32, &key_id);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    key_ready = true;

    status = encrypt
                 ? psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CBC_NO_PADDING)
                 : psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CBC_NO_PADDING);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    if (psa_cipher_set_iv(&operation, iv, sizeof iv) != PSA_SUCCESS) {
        goto cleanup;
    }
    if (psa_cipher_update(&operation, input, length, output, length, &output_length) !=
        PSA_SUCCESS) {
        goto cleanup;
    }
    if (psa_cipher_finish(&operation, output + output_length, length - output_length,
                          &finish_length) != PSA_SUCCESS) {
        goto cleanup;
    }
    ok = (output_length + finish_length) == length;

cleanup:
    psa_cipher_abort(&operation);
    psa_reset_key_attributes(&attributes);
    if (key_ready) {
        psa_destroy_key(key_id);
    }
    if (!ok) {
        memset(output, 0, length);
    }
    memset(iv, 0, sizeof iv);
    return ok;
}

bool pin_uv_check_pin_hash(const uint8_t hash[16])
{
    return pin_set && hash != NULL && memcmp(stored_pin_hash, hash, 16) == 0;
}

bool pin_uv_set_pin_hash(const uint8_t hash[16])
{
    if (hash == NULL) {
        return false;
    }
    memcpy(stored_pin_hash, hash, 16);
    pin_set = true;
    clear_ephemeral_key();
    pin_uv_clear_token();
    return persist_pin();
}
