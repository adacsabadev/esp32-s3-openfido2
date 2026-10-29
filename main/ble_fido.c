#include "ble_fido.h"
#include "u2f.h"
#include "sdkconfig.h"
#include "log.h"

#if defined(CONFIG_BT_ENABLED) && defined(CONFIG_BT_NIMBLE_ENABLED)

#include "ctap2.h"
#include "fido_ble_framing.h"
#include "indicators.h"
#include "log.h"
#include "platform.h"

#include "esp_app_desc.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "host/ble_att.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_store.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "os/os_mbuf.h"
#include "services/dis/ble_svc_dis.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include <stdio.h>
#include <string.h>

#define BLE_FIDO_FRAGMENT_CAP 244u
#define BLE_FIDO_RX_QUEUE_LENGTH 8u
#define BLE_FIDO_REASSEMBLY_TIMEOUT_MS 3000u
#define BLE_FIDO_KEEPALIVE_MS 500u
#define BLE_FIDO_PAIRING_WINDOW_MS 60000u
#define BLE_FIDO_CHANNEL_BASE 0xb1e00000u

enum {
    BLE_FIDO_PING = 0x81,
    BLE_FIDO_KEEPALIVE = 0x82,
    BLE_FIDO_MSG = 0x83,
    BLE_FIDO_CANCEL = 0xbe,
    BLE_FIDO_ERROR = 0xbf,
    BLE_FIDO_ERR_INVALID_CMD = 0x01,
    BLE_FIDO_ERR_INVALID_PAR = 0x02,
    BLE_FIDO_ERR_REQ_TIMEOUT = 0x05,
    BLE_FIDO_ERR_BUSY = 0x06,
};

typedef struct {
    uint16_t connection;
    uint16_t length;
    uint8_t data[BLE_FIDO_FRAGMENT_CAP];
} ble_fido_rx_fragment;

static const ble_uuid16_t fido_service_uuid = BLE_UUID16_INIT(0xfffd);
static const ble_uuid128_t control_point_uuid = BLE_UUID128_INIT(
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf1, 0xff, 0xd0, 0xf1);
static const ble_uuid128_t status_uuid = BLE_UUID128_INIT(
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf2, 0xff, 0xd0, 0xf1);
static const ble_uuid128_t control_point_length_uuid = BLE_UUID128_INIT(
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf3, 0xff, 0xd0, 0xf1);
static const ble_uuid128_t revision_bitfield_uuid = BLE_UUID128_INIT(
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf4, 0xff, 0xd0, 0xf1);

static QueueHandle_t rx_queue;
static fido_ble_reassembly reassembly;
static uint16_t status_value_handle;
static uint16_t connection_handle = BLE_HS_CONN_HANDLE_NONE;
static uint8_t own_address_type;
static volatile bool initialized;
static volatile bool secure_connection;
static volatile bool notifications_enabled;
static volatile bool revision_selected;
static volatile bool command_active;
static volatile bool pending;
static volatile bool pairing_mode;
static bool connection_was_bonded;
static uint32_t keepalive_time;
static uint32_t pairing_deadline;
static uint8_t response[FIDO_BLE_MESSAGE_CAP];

void ble_store_config_init(void);

static int fido_gatt_access(uint16_t connection, uint16_t attribute,
                            struct ble_gatt_access_ctxt *context, void *argument);

static const struct ble_gatt_svc_def fido_services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &fido_service_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = &control_point_uuid.u,
                .access_cb = fido_gatt_access,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {
                .uuid = &status_uuid.u,
                .access_cb = fido_gatt_access,
                .flags = BLE_GATT_CHR_F_NOTIFY |
                         BLE_GATT_CHR_F_NOTIFY_INDICATE_ENC,
                .val_handle = &status_value_handle,
            },
            {
                .uuid = &control_point_length_uuid.u,
                .access_cb = fido_gatt_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            {
                .uuid = &revision_bitfield_uuid.u,
                .access_cb = fido_gatt_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                         BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {0},
        },
    },
    {0},
};

static int bond_count(void)
{
    int count = 0;
    return ble_store_util_count(BLE_STORE_OBJ_TYPE_PEER_SEC, &count) == 0
               ? count : 0;
}

static bool peer_is_bonded(const ble_addr_t *peer)
{
    ble_addr_t peers[CONFIG_BT_NIMBLE_MAX_BONDS];
    int count = 0;
    if (ble_store_util_bonded_peers(peers, &count,
                                    CONFIG_BT_NIMBLE_MAX_BONDS) != 0) {
        return false;
    }
    for (int index = 0; index < count; ++index) {
        if (peers[index].type == peer->type &&
            memcmp(peers[index].val, peer->val, sizeof peer->val) == 0) {
            return true;
        }
    }
    return false;
}

static int append_value(struct os_mbuf *buffer, const void *value, uint16_t length)
{
    return os_mbuf_append(buffer, value, length) == 0
               ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int fido_gatt_access(uint16_t connection, uint16_t attribute,
                            struct ble_gatt_access_ctxt *context, void *argument)
{
    (void)attribute;
    (void)argument;
    const ble_uuid_t *uuid = context->chr->uuid;
    if (context->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        if (ble_uuid_cmp(uuid, &control_point_length_uuid.u) == 0) {
            const uint8_t length[] = {
                (uint8_t)(BLE_FIDO_FRAGMENT_CAP >> 8),
                (uint8_t)BLE_FIDO_FRAGMENT_CAP,
            };
            return append_value(context->om, length, sizeof length);
        }
        if (ble_uuid_cmp(uuid, &revision_bitfield_uuid.u) == 0) {
            const uint8_t revision = 0x20;
            return append_value(context->om, &revision, sizeof revision);
        }
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }
    if (context->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    uint16_t length = OS_MBUF_PKTLEN(context->om);
    if (ble_uuid_cmp(uuid, &revision_bitfield_uuid.u) == 0) {
        uint8_t revision = 0;
        if (length != 1u ||
            ble_hs_mbuf_to_flat(context->om, &revision, 1, 0) != 0 ||
            revision != 0x20u) {
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }
        revision_selected = true;
        return 0;
    }
    if (ble_uuid_cmp(uuid, &control_point_uuid.u) != 0) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }
    if (connection != connection_handle || length == 0u ||
        length > BLE_FIDO_FRAGMENT_CAP || rx_queue == 0) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    ble_fido_rx_fragment fragment = {
        .connection = connection,
        .length = length,
    };
    if (ble_hs_mbuf_to_flat(context->om, fragment.data,
                            sizeof fragment.data, 0) != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (xQueueSend(rx_queue, &fragment, 0) != pdTRUE) {
        return BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return 0;
}

static bool emit_notification(const uint8_t *fragment, uint16_t length,
                              void *context)
{
    (void)context;
    if (!secure_connection || !notifications_enabled ||
        connection_handle == BLE_HS_CONN_HANDLE_NONE) {
        return false;
    }
    struct os_mbuf *buffer = ble_hs_mbuf_from_flat(fragment, length);
    if (buffer == 0) {
        return false;
    }
    int result = ble_gatts_notify_custom(connection_handle,
                                         status_value_handle, buffer);
    return result == 0;
}

static bool send_frame(uint8_t command, const uint8_t *data, uint16_t length)
{
    uint16_t mtu_capacity = 20u;
    if (connection_handle != BLE_HS_CONN_HANDLE_NONE) {
        uint16_t mtu = ble_att_mtu(connection_handle);
        if (mtu > 3u) {
            mtu_capacity = (uint16_t)(mtu - 3u);
        }
    }
    if (mtu_capacity > BLE_FIDO_FRAGMENT_CAP) {
        mtu_capacity = BLE_FIDO_FRAGMENT_CAP;
    }
    return fido_ble_emit_frame(command, data, length, mtu_capacity,
                               emit_notification, 0);
}

static void send_error(uint8_t error)
{
    indicators_result(false);
    (void)send_frame(BLE_FIDO_ERROR, &error, 1);
}

static void send_keepalive(uint8_t status)
{
    (void)send_frame(BLE_FIDO_KEEPALIVE, &status, 1);
    keepalive_time = platform_millis();
}

static void reset_connection_state(void)
{
    if (pending) {
        ctap2_cancel();
    }
    pending = false;
    command_active = false;
    secure_connection = false;
    notifications_enabled = false;
    revision_selected = false;
    connection_was_bonded = false;
    connection_handle = BLE_HS_CONN_HANDLE_NONE;
    fido_ble_reassembly_reset(&reassembly);
    if (rx_queue != 0) {
        xQueueReset(rx_queue);
    }
}

static int gap_event(struct ble_gap_event *event, void *argument);

static void advertise(void)
{
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof fields);
    fields.flags = BLE_HS_ADV_F_BREDR_UNSUP |
                   (pairing_mode ? BLE_HS_ADV_F_DISC_GEN : 0u);
    fields.uuids16 = &fido_service_uuid;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    if (ble_gap_adv_set_fields(&fields) != 0) {
        log_puts("BLE FIDO advertising data failed\r\n");
        return;
    }

    uint8_t service_data[] = {0xfd, 0xff, pairing_mode ? 0x80u : 0x00u};
    memset(&fields, 0, sizeof fields);
    const char *name = ble_svc_gap_device_name();
    fields.name = (uint8_t *)name;
    fields.name_len = (uint8_t)strlen(name);
    fields.name_is_complete = 1;
    fields.svc_data_uuid16 = service_data;
    fields.svc_data_uuid16_len = sizeof service_data;
    if (ble_gap_adv_rsp_set_fields(&fields) != 0) {
        log_puts("BLE FIDO scan-response data failed\r\n");
        return;
    }

    struct ble_gap_adv_params parameters;
    memset(&parameters, 0, sizeof parameters);
    parameters.conn_mode = BLE_GAP_CONN_MODE_UND;
    parameters.disc_mode = pairing_mode ? BLE_GAP_DISC_MODE_GEN
                                        : BLE_GAP_DISC_MODE_NON;
    if (ble_gap_adv_start(own_address_type, 0, BLE_HS_FOREVER,
                          &parameters, gap_event, 0) != 0) {
        log_puts("BLE FIDO advertising start failed\r\n");
    } else {
        log_puts(pairing_mode ? "BLE FIDO advertising in pairing mode\r\n"
                              : "BLE FIDO advertising to bonded clients\r\n");
    }
}

static void restart_advertising(void)
{
    if (connection_handle != BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    if (ble_gap_adv_active()) {
        (void)ble_gap_adv_stop();
    }
    advertise();
}

static int gap_event(struct ble_gap_event *event, void *argument)
{
    (void)argument;
    struct ble_gap_conn_desc description;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status != 0) {
            advertise();
            return 0;
        }
        connection_handle = event->connect.conn_handle;
        secure_connection = false;
        notifications_enabled = false;
        revision_selected = false;
        if (ble_gap_conn_find(connection_handle, &description) != 0) {
            (void)ble_gap_terminate(connection_handle,
                                    BLE_ERR_REM_USER_CONN_TERM);
            return 0;
        }
        connection_was_bonded = peer_is_bonded(&description.peer_id_addr);
        if (!pairing_mode && !connection_was_bonded) {
            log_puts("BLE rejected unbonded client outside pairing mode\r\n");
            (void)ble_gap_terminate(connection_handle,
                                    BLE_ERR_REM_USER_CONN_TERM);
            return 0;
        }
        log_puts("BLE FIDO client connected; securing link\r\n");
        (void)ble_gap_security_initiate(connection_handle);
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        reset_connection_state();
        advertise();
        return 0;
    case BLE_GAP_EVENT_ENC_CHANGE:
        if (event->enc_change.status != 0 ||
            ble_gap_conn_find(event->enc_change.conn_handle,
                              &description) != 0 ||
            !description.sec_state.encrypted ||
            !description.sec_state.bonded) {
            log_puts("BLE FIDO link encryption/bonding failed\r\n");
            (void)ble_gap_terminate(event->enc_change.conn_handle,
                                    BLE_ERR_REM_USER_CONN_TERM);
            return 0;
        }
        secure_connection = true;
        log_puts("BLE FIDO encrypted bonded link ready\r\n");
        if (pairing_mode && !connection_was_bonded) {
            pairing_mode = false;
            pairing_deadline = 0;
        }
        return 0;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == status_value_handle) {
            notifications_enabled = event->subscribe.cur_notify != 0;
        }
        return 0;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        if (!pairing_mode ||
            ble_gap_conn_find(event->repeat_pairing.conn_handle,
                              &description) != 0) {
            return BLE_GAP_REPEAT_PAIRING_IGNORE;
        }
        (void)ble_store_util_delete_peer(&description.peer_id_addr);
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        advertise();
        return 0;
    default:
        return 0;
    }
}

static void on_reset(int reason)
{
    (void)reason;
    initialized = false;
    reset_connection_state();
    log_puts("BLE host reset\r\n");
}

static void on_sync(void)
{
    if (ble_hs_util_ensure_addr(0) != 0 ||
        ble_hs_id_infer_auto(1, &own_address_type) != 0) {
        log_puts("BLE identity/private address setup failed\r\n");
        return;
    }
    pairing_mode = bond_count() == 0;
    pairing_deadline = 0;
    initialized = true;
    advertise();
}

static void host_task(void *argument)
{
    (void)argument;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void ble_fido_init(void)
{
    rx_queue = xQueueCreate(BLE_FIDO_RX_QUEUE_LENGTH,
                            sizeof(ble_fido_rx_fragment));
    if (rx_queue == 0) {
        log_puts("BLE FIDO RX queue allocation failed\r\n");
        return;
    }
    fido_ble_reassembly_reset(&reassembly);
    if (nimble_port_init() != ESP_OK) {
        log_puts("BLE NimBLE initialization failed\r\n");
        return;
    }
    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                 BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                   BLE_SM_PAIR_KEY_DIST_ID;

    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_dis_init();
    if (ble_gatts_count_cfg(fido_services) != 0 ||
        ble_gatts_add_svcs(fido_services) != 0 ||
        ble_svc_gap_device_name_set("OpenFIDO2") != 0) {
        log_puts("BLE FIDO GATT service initialization failed\r\n");
        return;
    }
    const esp_app_desc_t *description = esp_app_get_description();
    (void)ble_svc_dis_manufacturer_name_set("OpenFIDO2");
    (void)ble_svc_dis_model_number_set("ESP32-S3");
    (void)ble_svc_dis_firmware_revision_set(description->version);
    ble_store_config_init();
    nimble_port_freertos_init(host_task);
}

void ble_fido_processing_tick(void)
{
    if (command_active && secure_connection && notifications_enabled &&
        (uint32_t)(platform_millis() - keepalive_time) >=
            BLE_FIDO_KEEPALIVE_MS) {
        send_keepalive(1);
    }
}

static void dispatch_complete_request(uint8_t command)
{
    if (command == BLE_FIDO_CANCEL) {
        if (pending) {
            ctap2_cancel();
            pending = false;
            response[0] = 0x2d;
            (void)send_frame(BLE_FIDO_MSG, response, 1);
        }
        return;
    }
    if (pending || ctap2_waiting() || u2f_waiting()) {
        send_error(BLE_FIDO_ERR_BUSY);
        return;
    }
    if (!revision_selected || !notifications_enabled || !secure_connection) {
        send_error(BLE_FIDO_ERR_INVALID_PAR);
        return;
    }
    if (command == BLE_FIDO_PING) {
        (void)send_frame(BLE_FIDO_PING, reassembly.data, reassembly.size);
        return;
    }
    if (command != BLE_FIDO_MSG) {
        send_error(BLE_FIDO_ERR_INVALID_CMD);
        return;
    }
    command_active = true;
    keepalive_time = platform_millis();
    uint16_t length = ctap2_dispatch(
        reassembly.data, reassembly.size, response, sizeof response,
        BLE_FIDO_CHANNEL_BASE | connection_handle);
    command_active = false;
    if (length) {
        indicators_result(response[0] == 0);
        (void)send_frame(BLE_FIDO_MSG, response, length);
    } else if (ctap2_waiting()) {
        pending = true;
        keepalive_time = platform_millis() - BLE_FIDO_KEEPALIVE_MS;
    } else {
        response[0] = 0x03;
        indicators_result(false);
        (void)send_frame(BLE_FIDO_MSG, response, 1);
    }
}

void ble_fido_poll(void)
{
    if (!initialized) {
        return;
    }
    uint32_t now = platform_millis();
    if (pairing_mode && pairing_deadline &&
        (int32_t)(now - pairing_deadline) >= 0 && bond_count() != 0) {
        pairing_mode = false;
        pairing_deadline = 0;
        restart_advertising();
    }
    if (fido_ble_reassembly_timed_out(&reassembly, now,
                                      BLE_FIDO_REASSEMBLY_TIMEOUT_MS)) {
        fido_ble_reassembly_reset(&reassembly);
        send_error(BLE_FIDO_ERR_REQ_TIMEOUT);
    }
    ble_fido_rx_fragment fragment;
    while (xQueueReceive(rx_queue, &fragment, 0) == pdTRUE) {
        if (fragment.connection != connection_handle) {
            continue;
        }
        indicators_activity();
        fido_ble_fragment_outcome value = fido_ble_receive_fragment(
            &reassembly, fragment.data, fragment.length, now);
        if (value.result == FIDO_BLE_FRAGMENT_ERROR) {
            send_error(value.error);
        } else if (value.result == FIDO_BLE_FRAGMENT_COMPLETE) {
            dispatch_complete_request(value.command);
        }
    }
    if (pending) {
        if ((uint32_t)(now - keepalive_time) >= BLE_FIDO_KEEPALIVE_MS) {
            send_keepalive(2);
        }
        uint16_t length = ctap2_poll(response, sizeof response);
        if (length) {
            pending = false;
            indicators_result(response[0] == 0);
            (void)send_frame(BLE_FIDO_MSG, response, length);
        }
    }
}

bool ble_fido_pairing_start(void)
{
    if (!initialized || bond_count() >= CONFIG_BT_NIMBLE_MAX_BONDS) {
        return false;
    }
    pairing_mode = true;
    pairing_deadline = platform_millis() + BLE_FIDO_PAIRING_WINDOW_MS;
    if (connection_handle != BLE_HS_CONN_HANDLE_NONE) {
        (void)ble_gap_security_initiate(connection_handle);
    } else {
        restart_advertising();
    }
    return true;
}

void ble_fido_log_status(void)
{
    char line[176];
    snprintf(line, sizeof line,
             "BLE initialized=%s advertising=%s connected=%s encrypted=%s "
             "notifications=%s pairing=%s bonds=%d\r\n",
             initialized ? "yes" : "no",
             initialized && ble_gap_adv_active() ? "yes" : "no",
             connection_handle == BLE_HS_CONN_HANDLE_NONE ? "no" : "yes",
             secure_connection ? "yes" : "no",
             notifications_enabled ? "yes" : "no",
             pairing_mode ? "yes" : "no", bond_count());
    log_puts(line);
}

#else

/* Keep the transport API available to USB and the diagnostic console. */
void ble_fido_init(void) { log_puts("BLE disabled in build configuration\r\n"); }
void ble_fido_poll(void) {}
void ble_fido_processing_tick(void) {}
bool ble_fido_pairing_start(void) { return false; }
void ble_fido_log_status(void) { log_puts("BLE disabled in build configuration\r\n"); }

#endif
