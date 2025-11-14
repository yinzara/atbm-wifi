/*
 * BLE Host Synchronization Callback
 *
 * Handles BLE stack synchronization and starts Improv WiFi advertising
 */

#include <assert.h>
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "improv_gatt_service.h"

static const char gap_name[] = "ble_fpga";
static uint8_t own_addr_type;
static int ble_hci_sync_ok = 0;

static void app_ble_sync_cb(void)
{
#ifdef CFG_B2B_SIMU
    extern void hci_test_app(void);
    hci_test_app();
#else
    int rc;
    rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    assert(rc == 0);

    ble_hci_sync_ok = 1;
#endif

    /* Start Improv WiFi advertising after BLE stack sync completes */
    improv_gatt_service_start();
}

void nimble_host_task(void *param)
{
    ble_hs_cfg.sync_cb = app_ble_sync_cb;

    iot_printf("nimble_host_task\n");

    nimble_port_run();
}

void ble_hci_sync_init(void)
{
    ble_hci_sync_ok = 0;
}

int ble_hci_sync_get(void)
{
    return ble_hci_sync_ok;
}
