#pragma once
#include <stdint.h>
#include "cbor_min.h"
uint16_t cred_mgmt_dispatch(cb_view root,uint8_t*out,uint16_t capacity,uint32_t channel);
void cred_mgmt_cancel(void);
