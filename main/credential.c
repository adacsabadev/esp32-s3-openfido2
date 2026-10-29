#include "credential.h"

#include "ctaphid.h"
#include "esp_random.h"
#include "log.h"

#include "psa/crypto.h"

#include <stddef.h>
#include <string.h>

#define CREDENTIAL_MAGIC 0x32444946u
#define CREDENTIAL_COMMIT 0x434f4d54u

static bool psa_initialized;

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

static size_t trim_integer_length(const uint8_t *value, size_t value_len)
{
    size_t offset = 0;
    while (offset + 1 < value_len && value[offset] == 0) {
        offset++;
    }
    return value_len - offset;
}

static bool ecdsa_raw_to_der(const uint8_t raw[64], uint8_t der[80], size_t *der_len)
{
    size_t r_value_len = trim_integer_length(raw, 32);
    size_t s_value_len = trim_integer_length(raw + 32, 32);
    bool r_needs_pad = (raw[32 - r_value_len] & 0x80u) != 0;
    bool s_needs_pad = (raw[64 - s_value_len] & 0x80u) != 0;
    size_t r_der_len = r_value_len + (r_needs_pad ? 1u : 0u);
    size_t s_der_len = s_value_len + (s_needs_pad ? 1u : 0u);
    size_t seq_len = 2u + r_der_len + 2u + s_der_len;

    if (seq_len > 78u || der_len == NULL) {
        return false;
    }

    der[0] = 0x30;
    der[1] = (uint8_t)seq_len;
    der[2] = 0x02;
    der[3] = (uint8_t)r_der_len;

    size_t index = 4u;
    if (r_needs_pad) {
        der[index++] = 0;
    }
    memcpy(der + index, raw + (32u - r_value_len), r_value_len);
    index += r_value_len;

    der[index++] = 0x02;
    der[index++] = (uint8_t)s_der_len;
    if (s_needs_pad) {
        der[index++] = 0;
    }
    memcpy(der + index, raw + 32u + (32u - s_value_len), s_value_len);
    index += s_value_len;

    *der_len = index;
    return true;
}

void crypto_hash(const void *p, size_t n, uint8_t out[32])
{
    size_t hash_length = 0;
    if (out == NULL || p == NULL || !crypto_init() ||
        psa_hash_compute(PSA_ALG_SHA_256, p, n, out, 32, &hash_length) != PSA_SUCCESS ||
        hash_length != 32) {
        if (out != NULL) {
            memset(out, 0, 32);
        }
    }
}

int crypto_random(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    if (out == NULL && n != 0) {
        return -1;
    }
    ctaphid_processing_tick();
    esp_fill_random(out, n);
    ctaphid_processing_tick();
    return 0;
}

bool credential_storage_init(void)
{
    return credential_store_init() && crypto_init();
}

bool crypto_generate(credential *c, uint8_t x[32], uint8_t y[32])
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t public_key[65];
    size_t public_key_len = 0;
    size_t private_key_len = 0;
    bool key_ready = false;
    bool ok = false;

    if (c == NULL || x == NULL || y == NULL || !crypto_init()) {
        return false;
    }

    memset(public_key, 0, sizeof public_key);
    memset(c->secret, 0, sizeof c->secret);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    if (psa_generate_key(&attributes, &key_id) != PSA_SUCCESS) {
        goto cleanup;
    }
    key_ready = true;
    if (psa_export_public_key(key_id, public_key, sizeof public_key, &public_key_len) != PSA_SUCCESS ||
        public_key_len != sizeof public_key || public_key[0] != 0x04) {
        goto cleanup;
    }
    if (psa_export_key(key_id, c->secret, sizeof c->secret, &private_key_len) != PSA_SUCCESS ||
        private_key_len != sizeof c->secret) {
        goto cleanup;
    }

    if (crypto_random(NULL, c->id, sizeof c->id) != 0) {
        goto cleanup;
    }
    memcpy(x, public_key + 1, 32);
    memcpy(y, public_key + 33, 32);
    c->magic = CREDENTIAL_MAGIC;
    c->sequence++;
    c->counter = 1;
    c->commit = CREDENTIAL_COMMIT;
    crypto_hash(c, offsetof(credential, digest), c->digest);
    ok = true;

cleanup:
    psa_reset_key_attributes(&attributes);
    if (key_ready) {
        psa_destroy_key(key_id);
    }
    if (!ok) {
        memset(c->secret, 0, sizeof c->secret);
        memset(x, 0, 32);
        memset(y, 0, 32);
    }
    memset(public_key, 0, sizeof public_key);
    return ok;
}

bool crypto_sign(const credential *c, const uint8_t *data, size_t n,
                 uint8_t sig[80], size_t *len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t digest[32];
    uint8_t raw_sig[64];
    size_t raw_sig_len = 0;
    bool key_ready = false;
    bool ok = false;

    if (c == NULL || data == NULL || sig == NULL || len == NULL || !crypto_init()) {
        return false;
    }

    memset(digest, 0, sizeof digest);
    memset(raw_sig, 0, sizeof raw_sig);

    size_t hash_length = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, data, n, digest, sizeof digest,
                         &hash_length) != PSA_SUCCESS || hash_length != sizeof digest) {
        goto cleanup;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    if (psa_import_key(&attributes, c->secret, sizeof c->secret, &key_id) != PSA_SUCCESS) {
        goto cleanup;
    }
    key_ready = true;
    if (psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest, sizeof digest,
                      raw_sig, sizeof raw_sig, &raw_sig_len) != PSA_SUCCESS ||
        raw_sig_len != sizeof raw_sig) {
        goto cleanup;
    }
    ok = ecdsa_raw_to_der(raw_sig, sig, len);

cleanup:
    psa_reset_key_attributes(&attributes);
    if (key_ready) {
        psa_destroy_key(key_id);
    }
    memset(digest, 0, sizeof digest);
    memset(raw_sig, 0, sizeof raw_sig);
    return ok;
}

/* Derive the public point from the existing private scalar. */
bool crypto_public_key(const credential *c,uint8_t x[32],uint8_t y[32])
{
    psa_key_attributes_t attributes=PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key=MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t encoded[65];size_t length=0;
    if(!c || !x || !y || !crypto_init())return false;
    psa_set_key_type(&attributes,PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes,256);
    bool imported=psa_import_key(&attributes,c->secret,32,&key)==PSA_SUCCESS;
    bool ok=imported && psa_export_public_key(key,encoded,sizeof encoded,&length)==PSA_SUCCESS
        && length==65 && encoded[0]==4;
    if(ok){memcpy(x,encoded+1,32);memcpy(y,encoded+33,32);}
    else {memset(x,0,32);memset(y,0,32);}
    if(imported)psa_destroy_key(key);
    psa_reset_key_attributes(&attributes);memset(encoded,0,sizeof encoded);return ok;
}
