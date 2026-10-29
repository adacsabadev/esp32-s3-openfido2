#include "pin_uv.h"
#include "platform.h"
#include <string.h>

static uint8_t pin_token[32];
static bool token_ready;
static uint8_t token_permissions,token_rp[32];
static bool token_rp_bound;
static uint32_t token_created,token_serial;

bool pin_uv_set_token(const uint8_t token[32])
{
    return pin_uv_set_scoped_token(token,3,NULL);
}

bool pin_uv_set_scoped_token(const uint8_t token[32],uint8_t permissions,
                             const uint8_t rp_hash[32])
{
    if (token == NULL) {
        return false;
    }
    memcpy(pin_token, token, 32);
    token_ready = true;
    token_permissions=permissions;
    token_rp_bound=rp_hash!=NULL;
    if(rp_hash)memcpy(token_rp,rp_hash,32);else memset(token_rp,0,32);
    token_created=platform_millis();token_serial++;
    return true;
}

bool pin_uv_verify_token_auth(const uint8_t *data, size_t length,
                              const uint8_t auth[16])
{
    uint8_t expected[32];
    bool valid;

    if (!pin_uv_token_permits(0,token_rp_bound?token_rp:NULL) || auth == NULL || (length != 0 && data == NULL)) {
        return false;
    }
    if (!pin_uv_hmac(pin_token, data, length, expected)) {
        return false;
    }
    uint8_t difference=0;
    for(unsigned i=0;i<16;i++)difference|=expected[i]^auth[i];
    valid = difference==0;
    memset(expected, 0, sizeof expected);
    return valid;
}

void pin_uv_clear_token(void)
{
    memset(pin_token, 0, sizeof pin_token);
    token_ready = false;
    token_permissions=0;token_rp_bound=false;memset(token_rp,0,32);token_serial++;
}

bool pin_uv_token_has_permission(uint8_t permission)
{
    if(token_ready && (uint32_t)(platform_millis()-token_created)>=30000)
        pin_uv_clear_token();
    return token_ready && (token_permissions&permission)==permission;
}
bool pin_uv_token_permits(uint8_t permission,const uint8_t rp_hash[32])
{
    return pin_uv_token_has_permission(permission) &&
        (!token_rp_bound || (rp_hash && !memcmp(token_rp,rp_hash,32)));
}
bool pin_uv_authorize_rp(uint8_t permission,const uint8_t rp_hash[32])
{
    if(!pin_uv_token_permits(permission,rp_hash))return false;
    if(!token_rp_bound){memcpy(token_rp,rp_hash,32);token_rp_bound=true;}
    return true;
}
uint32_t pin_uv_token_generation(void) { return token_serial; }
