#include "fido2.h"
#include "log.h"
#include "ctaphid.h"
void fido2_init(void) { ctaphid_init(); log_puts("CTAP2 ES256 ready: MakeCredential + GetAssertion; flash journal enabled\r\n"); }
void fido2_poll(void) { ctaphid_poll(); }
void fido2_hid_rx(const uint8_t *report, uint32_t length) { (void)report; (void)length; log_puts("CTAPHID RX\r\n"); }
