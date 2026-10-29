#include "u2f_attestation.h"
#include "u2f_cert_template.h"
#include "credential.h"
#include "nvs.h"
#include <string.h>

static credential attestation;
static uint8_t certificate[512];
static size_t certificate_length;
static const uint8_t algorithm[] = {
    0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02
};

static bool initialize(void)
{
    if (certificate_length) return true;
    nvs_handle_t handle;
    if (nvs_open("u2f_attest", NVS_READWRITE, &handle) != ESP_OK) return false;
    size_t length = sizeof attestation.secret;
    esp_err_t result = nvs_get_blob(handle, "scalar", attestation.secret, &length);
    uint8_t point[65] = {4};
    bool ok = false;
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        if (!crypto_generate(&attestation, point+1, point+33)) goto done;
        if (nvs_set_blob(handle, "scalar", attestation.secret, 32) != ESP_OK ||
            nvs_commit(handle) != ESP_OK) goto done;
        uint8_t check[32];
        length = sizeof check;
        if (nvs_get_blob(handle, "scalar", check, &length) != ESP_OK ||
            length != 32 || memcmp(check, attestation.secret, 32)) {
            memset(check, 0, sizeof check);
            goto done;
        }
        memset(check, 0, sizeof check);
    } else if (result != ESP_OK || length != 32) {
        goto done; /* Never silently replace an invalid persisted identity. */
    }
    if (!crypto_public_key(&attestation, point+1, point+33)) goto done;
    uint8_t tbs[sizeof u2f_cert_tbs_template], digest[32], signature[80];
    size_t signature_length = 0;
    memcpy(tbs, u2f_cert_tbs_template, sizeof tbs);
    memcpy(tbs + U2F_CERT_POINT_OFFSET, point, sizeof point);
    crypto_hash(point, sizeof point, digest);
    digest[0] = (digest[0] & 0x7f) | 1;
    memcpy(tbs + U2F_CERT_SERIAL_OFFSET, digest, 20);
    if (!crypto_sign(&attestation, tbs, sizeof tbs, signature, &signature_length) ||
        signature_length > 80) goto done;
    size_t body = sizeof tbs + sizeof algorithm + 3 + signature_length;
    if (body + 4 > sizeof certificate || body > 65535) goto done;
    certificate[0] = 0x30; certificate[1] = 0x82;
    certificate[2] = (uint8_t)(body >> 8); certificate[3] = (uint8_t)body;
    size_t offset = 4;
    memcpy(certificate+offset, tbs, sizeof tbs); offset += sizeof tbs;
    memcpy(certificate+offset, algorithm, sizeof algorithm); offset += sizeof algorithm;
    certificate[offset++] = 3;
    certificate[offset++] = (uint8_t)(signature_length + 1);
    certificate[offset++] = 0;
    memcpy(certificate+offset, signature, signature_length);
    certificate_length = offset + signature_length;
    ok = true;
done:
    nvs_close(handle);
    if (!ok) memset(&attestation, 0, sizeof attestation);
    return ok;
}

bool u2f_attestation_certificate(const uint8_t **out, size_t *length)
{
    if (!out || !length || !initialize()) return false;
    *out = certificate; *length = certificate_length;
    return true;
}

bool u2f_attestation_sign(const uint8_t *data, size_t length,
                          uint8_t signature[80], size_t *signature_length)
{
    return initialize() && crypto_sign(&attestation, data, length, signature, signature_length);
}
