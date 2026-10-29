#include "u2f.h"
#include "u2f_attestation.h"
#include "credential.h"
#include "indicators.h"
#include "platform.h"
#include <string.h>

#define TOUCH_TIMEOUT_MS 30000u
#define HANDLE_LENGTH 36u
static const uint8_t handle_prefix[4] = {'U','2','F',1};
static struct { bool active; uint32_t channel, started; uint8_t digest[32]; } touch;

static uint16_t status(uint8_t *out, uint16_t word)
{
    out[0] = (uint8_t)(word >> 8); out[1] = (uint8_t)word;
    return 2;
}

void u2f_cancel(uint32_t channel)
{
    if (touch.active && (!channel || channel == touch.channel)) {
        memset(&touch, 0, sizeof touch);
        presence_cancel();
    }
}

void u2f_poll(void)
{
    if (touch.active && (uint32_t)(platform_millis()-touch.started) >= TOUCH_TIMEOUT_MS)
        u2f_cancel(0);
}

bool u2f_waiting(void) { u2f_poll(); return touch.active; }
bool u2f_channel_active(uint32_t channel)
{ return u2f_waiting() && touch.channel == channel; }

static bool approve(const uint8_t *request, uint16_t length, uint32_t channel)
{
    uint8_t digest[32];
    crypto_hash(request, length, digest);
    u2f_poll();
    if (touch.active && touch.channel != channel) return false;
    if (!touch.active || memcmp(touch.digest, digest, 32)) {
        u2f_cancel(0);
        touch.active = true; touch.channel = channel; touch.started = platform_millis();
        memcpy(touch.digest, digest, 32);
        presence_begin();
        return false;
    }
    if (!presence_take()) return false;
    u2f_cancel(0);
    return true;
}

static uint16_t registration(const uint8_t *data, uint8_t *out, uint16_t capacity)
{
    credential key = {0};
    uint8_t point[65] = {4}, handle[HANDLE_LENGTH], signature[80];
    uint8_t signed_data[1+32+32+HANDLE_LENGTH+65];
    const uint8_t *cert;
    size_t cert_length, signature_length = 0;
    uint16_t result = 2;
    status(out, 0x6f00);
    if (!credential_room_for(1) ||
        !u2f_attestation_certificate(&cert, &cert_length)) goto done;
    if (cert_length > 512 || capacity < 1+65+1+HANDLE_LENGTH+cert_length+80+2) {
        status(out, 0x6700); goto done;
    }
    memcpy(key.rp, data+32, 32);
    if (!crypto_generate(&key, point+1, point+33)) goto done;
    key.counter = 0;
    memcpy(handle, handle_prefix, 4); memcpy(handle+4, key.id, 32);
    signed_data[0] = 0;
    memcpy(signed_data+1, data+32, 32);
    memcpy(signed_data+33, data, 32);
    memcpy(signed_data+65, handle, HANDLE_LENGTH);
    memcpy(signed_data+65+HANDLE_LENGTH, point, 65);
    if (!u2f_attestation_sign(signed_data, sizeof signed_data, signature, &signature_length) ||
        signature_length > sizeof signature || !credential_save(&key)) goto done;
    size_t offset = 0;
    out[offset++] = 5;
    memcpy(out+offset, point, 65); offset += 65;
    out[offset++] = HANDLE_LENGTH;
    memcpy(out+offset, handle, HANDLE_LENGTH); offset += HANDLE_LENGTH;
    memcpy(out+offset, cert, cert_length); offset += cert_length;
    memcpy(out+offset, signature, signature_length); offset += signature_length;
    status(out+offset, 0x9000); result = (uint16_t)(offset+2);
done:
    memset(&key, 0, sizeof key);
    indicators_result(result > 2);
    return result;
}

static uint16_t authenticate(const uint8_t *request, uint16_t length,
                             uint8_t *out, uint16_t capacity, uint32_t channel)
{
    const uint8_t *data = request+7;
    credential key = {0};
    uint16_t result = 2;
    if (data[64] != HANDLE_LENGTH || memcmp(data+65, handle_prefix, 4) ||
        !credential_lookup(data+69, data+32, &key)) {
        return status(out, 0x6a80);
    }
    if (request[2] == 7) { result = status(out, 0x6985); goto done; }
    if (capacity < 5+80+2) { result = status(out, 0x6700); goto done; }
    if (key.counter == UINT32_MAX) { result = status(out, 0x6f00); goto done; }
    bool presence = request[2] == 3;
    if (presence && !approve(request, length, channel)) {
        result = status(out, 0x6985); goto done;
    }
    if (!presence) u2f_cancel(channel);
    uint8_t signed_data[69], signature[80];
    size_t signature_length = 0;
    key.counter++;
    memcpy(signed_data, data+32, 32);
    signed_data[32] = presence ? 1 : 0;
    signed_data[33] = (uint8_t)(key.counter >> 24);
    signed_data[34] = (uint8_t)(key.counter >> 16);
    signed_data[35] = (uint8_t)(key.counter >> 8);
    signed_data[36] = (uint8_t)key.counter;
    memcpy(signed_data+37, data, 32);
    /* Never publish a response before its counter is committed. */
    if (!crypto_sign(&key, signed_data, sizeof signed_data, signature, &signature_length) ||
        signature_length > sizeof signature || !credential_save(&key)) {
        result = status(out, 0x6f00); indicators_result(false); goto done;
    }
    memcpy(out, signed_data+32, 5);
    memcpy(out+5, signature, signature_length);
    status(out+5+signature_length, 0x9000);
    result = (uint16_t)(7+signature_length);
    indicators_result(true);
done:
    memset(&key, 0, sizeof key);
    return result;
}

uint16_t u2f_dispatch(const uint8_t *request, uint16_t length,
                      uint8_t *response, uint16_t capacity, uint32_t channel)
{
    if (!response || capacity < 2) return 0;
    if (!request || length < 7) return status(response, 0x6700);
    if (request[0]) return status(response, 0x6e00);
    uint32_t data_length = ((uint32_t)request[4] << 16) |
                           ((uint32_t)request[5] << 8) | request[6];
    uint32_t end = 7u + data_length;
    if (end != length && end+2u != length) return status(response, 0x6700);
    switch (request[1]) {
    case 1:
        if (request[2] || request[3]) return status(response, 0x6a86);
        if (data_length != 64) return status(response, 0x6700);
        if (capacity < 700) return status(response, 0x6700);
        if (!approve(request, length, channel)) return status(response, 0x6985);
        return registration(request+7, response, capacity);
    case 2:
        if (request[3] || (request[2]!=3 && request[2]!=7 && request[2]!=8))
            return status(response, 0x6a86);
        if (data_length < 65 || data_length != 65u+request[71])
            return status(response, 0x6700);
        return authenticate(request, length, response, capacity, channel);
    case 3:
        if (request[2] || request[3]) return status(response, 0x6a86);
        if (data_length || capacity < 8) return status(response, 0x6700);
        memcpy(response, "U2F_V2", 6); status(response+6, 0x9000); return 8;
    default:
        return status(response, 0x6d00);
    }
}
