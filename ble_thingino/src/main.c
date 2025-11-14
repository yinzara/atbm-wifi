/*
 * Thingino BLE GATT Server - Improv WiFi Provisioning
 *
 * Main entry point for the BLE GATT server that provides Improv WiFi
 * provisioning functionality for Thingino devices.
 */

#include "ble_hci_ram.h"
#include "nimble/nimble_port.h"
#include "syscfg/syscfg.h"
#include "host/ble_hs.h"
#include "atbm_nimble_api.h"
#include "improv_gatt_service.h"

extern void nimble_host_task(void *param);
extern void nimble_port_init(void);
extern void nimble_port_atbmos_init(atbm_void(* host_task_fn));
extern void cli_init(void);
void cli_free(void);
void nimble_port_atbmos_free(void);
void ble_hci_sync_init(void);
int ble_hci_sync_get(void);

/* Global variables */
char connect_ap[64];
int force_service_registration = 0;  /* Global flag for -f option */
int should_exit_after_init = 0;      /* Set if provisioned and not forced */

void ble_gatt_svcs_init(void)
{
    /* Check provisioning status FIRST before doing anything */
    extern int check_provisioning_status_early(void);

    int is_provisioned = check_provisioning_status_early();

    if (is_provisioned && !force_service_registration) {
        iot_printf("[MAIN] *** DEVICE ALREADY PROVISIONED - SKIPPING BLE SERVICE INIT ***\n");
        iot_printf("[MAIN] *** Use -f flag to force BLE service startup ***\n");
        should_exit_after_init = 1;
        return;
    }

    if (is_provisioned && force_service_registration) {
        iot_printf("[MAIN] *** FORCE MODE - DEVICE IS PROVISIONED BUT STARTING ANYWAY ***\n");
    }

    /* Clear any old GATT services from previous sessions */
    extern int ble_gatts_reset(void);
    ble_gatts_reset();
    iot_printf("[MAIN] *** GATT DATABASE RESET - CLEARED ALL OLD SERVICES ***\n");

    /* Initialize Improv WiFi service (advertising will start in sync callback) */
    improv_gatt_service_init();
}

int nimble_main(void)
{
    nimble_port_init();
    ble_gatt_svcs_init();

    /* Only start the BLE host task if we're not exiting */
    if (!should_exit_after_init) {
        nimble_port_atbmos_init(nimble_host_task);
    }

    if (!should_exit_after_init) {
        cli_init();
    }

    return 0;
}

void nimble_release(void)
{
    if (!should_exit_after_init) {
        cli_free();
    }
    nimble_port_atbmos_free();
    nimble_port_release();
    ble_gap_free();
    ble_hs_hci_free();
    ble_hs_free();
}

int main(int argc, char *argv[])
{
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            force_service_registration = 1;
            iot_printf("[MAIN] Force mode enabled - will register services even if provisioned\n");
        } else {
            memcpy(connect_ap, argv[i], strlen(argv[i]));
            printf("connect_ap file: %s ,%s,%d\n", connect_ap, argv[i], strlen(argv[i]));
        }
    }

    iot_printf("======>>atbm_ble_start>>>\n");
    nimble_main();

    /* Check if we should exit because device is already provisioned */
    if (should_exit_after_init) {
        iot_printf("[MAIN] ===============================================\n");
        iot_printf("[MAIN] *** DEVICE FULLY PROVISIONED - EXITING ***\n");
        iot_printf("[MAIN] *** Use -f flag to force BLE service startup ***\n");
        iot_printf("[MAIN] ===============================================\n");

        /* Exit cleanly - no cleanup needed since BLE stack was never started */
        iot_printf("[MAIN] Exiting cleanly.\n");
        return 0;
    }

    /* AT command initialization (disabled for Improv WiFi mode) */
    extern void atcmd_init_ble(void);
    atcmd_init_ble();

    /* HIF IOCTL initialization */
    extern void hif_ioctl_init(void);
    hif_ioctl_init();

    /* Start BLE host scheduler */
    extern void ble_hs_sched_start(void);
    ble_hs_sched_start();
    iot_printf("hif_ioctl_loop\n");

    /* Start ioctl loop to WiFi driver */
    extern void hif_ioctl_loop(void);
    hif_ioctl_loop();

    iot_printf("ble_hs_hci_cmd_reset\n");
    nimble_release();

    return 0;
}
